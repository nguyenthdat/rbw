#[cfg(target_os = "macos")]
mod imp {
    use security_framework::passwords::{
        AccessControlOptions, PasswordOptions,
        delete_generic_password_options, generic_password,
        set_generic_password_options,
    };
    use security_framework_sys::base::errSecItemNotFound;
    use zeroize::Zeroize as _;

    const SERVICE: &str = "rbw";

    fn options() -> PasswordOptions {
        PasswordOptions::new_generic_password(
            SERVICE,
            &crate::dirs::profile(),
        )
    }

    pub fn load() -> anyhow::Result<Option<crate::locked::Keys>> {
        let mut key = match generic_password(options()) {
            Ok(key) => key,
            Err(error) if error.code() == errSecItemNotFound => {
                return Ok(None);
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "failed to read Touch ID vault key from Keychain: {error}"
                ));
            }
        };
        if key.len() != 64 {
            key.zeroize();
            delete()?;
            return Ok(None);
        }

        let mut locked = crate::locked::Vec::new();
        locked.extend(key.iter().copied());
        key.zeroize();
        Ok(Some(crate::locked::Keys::new(locked)))
    }

    pub fn store(key: &crate::locked::Keys) -> anyhow::Result<()> {
        let mut options = options();
        options.set_access_control_options(
            AccessControlOptions::BIOMETRY_CURRENT_SET,
        );
        set_generic_password_options(key.bytes(), options).map_err(|error| {
            anyhow::anyhow!(
                "failed to store Touch ID vault key in Keychain: {error}"
            )
        })
    }

    pub fn delete() -> anyhow::Result<()> {
        match delete_generic_password_options(options()) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == errSecItemNotFound => Ok(()),
            Err(error) => Err(anyhow::anyhow!(
                "failed to delete Touch ID vault key from Keychain: {error}"
            )),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn load() -> anyhow::Result<Option<crate::locked::Keys>> {
        Ok(None)
    }

    pub fn store(_key: &crate::locked::Keys) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn delete() -> anyhow::Result<()> {
        Ok(())
    }
}

pub fn load() -> anyhow::Result<Option<crate::locked::Keys>> {
    imp::load()
}

pub fn store(key: &crate::locked::Keys) -> anyhow::Result<()> {
    imp::store(key)
}

pub fn delete() -> anyhow::Result<()> {
    imp::delete()
}

#[cfg(test)]
mod tests {
    #[test]
    fn unsupported_platform_does_not_store_keys() {
        #[cfg(not(target_os = "macos"))]
        {
            let key = crate::locked::Keys::new({
                let mut value = crate::locked::Vec::new();
                value.extend(std::iter::repeat_n(0, 64));
                value
            });
            assert!(crate::touch_id::store(&key).is_ok());
            assert!(crate::touch_id::load().unwrap().is_none());
            assert!(crate::touch_id::delete().is_ok());
        }
    }
}
