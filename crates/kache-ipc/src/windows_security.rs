//! Admission requires the same unmodified primary-token security context.

use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub(crate) fn matches_daemon(process: BorrowedHandle<'_>) -> io::Result<bool> {
    let client = token(process.as_raw_handle(), TOKEN_QUERY)?;
    let daemon = token(unsafe { GetCurrentProcess() }, TOKEN_QUERY)?;
    equivalent(client.as_raw_handle(), daemon.as_raw_handle())
}

fn token(process: HANDLE, access: u32) -> io::Result<OwnedHandle> {
    let mut handle = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, access, &mut handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn information<T>(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<T> {
    let mut value = MaybeUninit::<T>::uninit();
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token,
            class,
            value.as_mut_ptr().cast(),
            size_of::<T>() as u32,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<T>() {
        return Err(io::Error::other(
            "unexpected compiler security context size",
        ));
    }
    Ok(unsafe { value.assume_init() })
}

fn equivalent(client: HANDLE, daemon: HANDLE) -> io::Result<bool> {
    if information::<u32>(client, TokenIsAppContainer)? != 0
        || information::<u32>(daemon, TokenIsAppContainer)? != 0
    {
        return Ok(false);
    }
    let client = information::<TOKEN_STATISTICS>(client, TokenStatistics)?;
    let server = information::<TOKEN_STATISTICS>(daemon, TokenStatistics)?;
    let luid = |value: windows_sys::Win32::Foundation::LUID| (value.HighPart, value.LowPart);
    // ModifiedId is a kernel-issued LUID that changes whenever the token is
    // modified. Unchanged primary-token copies inherited by compiler clients
    // and the daemon retain this generation, including opaque claims. Require
    // that exact generation rather than trying to interpret reserved fields.
    // https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-token_statistics
    Ok(client.TokenType == TokenPrimary
        && server.TokenType == TokenPrimary
        && luid(client.AuthenticationId) == luid(server.AuthenticationId)
        && luid(client.ModifiedId) == luid(server.ModifiedId))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_primary_token_has_the_same_context() {
        let token = token(unsafe { GetCurrentProcess() }, TOKEN_QUERY).unwrap();
        assert!(equivalent(token.as_raw_handle(), token.as_raw_handle()).unwrap());
    }

    #[test]
    fn an_unmodified_primary_token_copy_has_the_same_context() {
        let token = token(
            unsafe { GetCurrentProcess() },
            TOKEN_QUERY | TOKEN_DUPLICATE,
        )
        .unwrap();
        let mut duplicate = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                DuplicateTokenEx(
                    token.as_raw_handle(),
                    TOKEN_QUERY,
                    std::ptr::null(),
                    SecurityImpersonation,
                    TokenPrimary,
                    &mut duplicate,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
        let duplicate = unsafe { OwnedHandle::from_raw_handle(duplicate) };
        let original =
            information::<TOKEN_STATISTICS>(token.as_raw_handle(), TokenStatistics).unwrap();
        let copied =
            information::<TOKEN_STATISTICS>(duplicate.as_raw_handle(), TokenStatistics).unwrap();
        assert_ne!(
            (original.TokenId.HighPart, original.TokenId.LowPart),
            (copied.TokenId.HighPart, copied.TokenId.LowPart)
        );
        assert!(equivalent(token.as_raw_handle(), duplicate.as_raw_handle()).unwrap());
    }

    #[test]
    fn deleting_privileges_cannot_use_an_unrestricted_daemon() {
        let token = token(
            unsafe { GetCurrentProcess() },
            TOKEN_QUERY | TOKEN_DUPLICATE,
        )
        .unwrap();
        let mut restricted = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                CreateRestrictedToken(
                    token.as_raw_handle(),
                    DISABLE_MAX_PRIVILEGE,
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    &mut restricted,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
        let restricted = unsafe { OwnedHandle::from_raw_handle(restricted) };
        assert!(!equivalent(restricted.as_raw_handle(), token.as_raw_handle()).unwrap());
        assert!(!equivalent(token.as_raw_handle(), restricted.as_raw_handle()).unwrap());
    }
}
