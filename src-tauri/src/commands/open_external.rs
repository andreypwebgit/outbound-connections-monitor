use tauri::command;

/// `true` solo para URLs http(s) sin caracteres que puedan alterar el
/// argumento pasado al sistema. Las URLs de la UI son fijas, pero el comando
/// valida por defensa en profundidad.
fn is_safe_external_url(url: &str) -> bool {
    (url.starts_with("https://") || url.starts_with("http://"))
        && !url.chars().any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '\'')
}

/// Abre una URL http(s) en el navegador por defecto del sistema.
///
/// Los enlaces `target="_blank"` de la webview no abren el navegador
/// predeterminado en Tauri 2/WebView2, así que la UI intercepta el click y
/// delega aquí. Se usa `rundll32 url.dll,FileProtocolHandler` (ShellExecute
/// con el manejador por defecto) porque recibe la URL como argumento directo,
/// sin pasar por un shell que interprete metacaracteres.
#[command]
pub async fn open_external(url: String) -> Result<(), String> {
    if !is_safe_external_url(&url) {
        return Err(format!("Refusing to open URL '{}': only plain http(s) URLs are allowed", url));
    }

    std::process::Command::new("rundll32.exe")
        .args(["url.dll,FileProtocolHandler", &url])
        .spawn()
        .map_err(|e| format!("Failed to open default browser: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_http_and_https() {
        assert!(is_safe_external_url("https://apwebai.es/"));
        assert!(is_safe_external_url("https://ard.apwebai.es"));
        assert!(is_safe_external_url("http://example.com/path?x=1"));
    }

    #[test]
    fn rejects_non_http_schemes_and_shell_metacharacters() {
        assert!(!is_safe_external_url("file:///C:/Windows/system32/calc.exe"));
        assert!(!is_safe_external_url("javascript:alert(1)"));
        assert!(!is_safe_external_url("C:\\Windows\\system32\\calc.exe"));
        assert!(!is_safe_external_url("https://x.com/a b"));
        assert!(!is_safe_external_url("https://x.com/\"quoted\""));
        assert!(!is_safe_external_url(""));
    }
}
