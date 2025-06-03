# V3 Безпека веб-фронтенду

## Мета контролю

Ця категорія зосереджена на вимогах, спрямованих на захист від атак, які здійснюються через веб-фронтенд. Ці вимоги не застосовуються до рішень типу "машина-до-машини".

## V3.1 Документація з безпеки веб-фронтенду

This section outlines the browser security features that should be specified in the application's documentation.
Ця секція описує особливості безпеки браузера, які мають бути вказані в документації застосунку.

| # | Опис | Рівень |
| :---: | :--- | :---: |
| **3.1.1** | Перевірити, що документація застосунку вказує на очікувані механізми безпеки, які мають підтримувати браузери, що використовують застосунок (наприклад, HTTPS, HTTP Strict Transport Security (HSTS), Content Security Policy (CSP) та інші відповідні HTTP-механізми безпеки). Також має бути визначено, як застосунок повинен поводитися у випадках відсутності деяких із цих механізмів (наприклад, попереджати користувача або блокувати доступ). | 3 |

## V3.2 Ненавмисне інтерпретування вмісту

Відображення вмісту або функціональності в неправильному контексті може призвести до виконання або відображення зловмисного контенту.

| # | Опис | Рівень |
| :---: | :--- | :---: |
| **3.2.1** | Перевірити, що впроваджено заходи безпеки, які запобігають відображенню браузером контенту або функціональності HTTP-відповідей у неправильному контексті (наприклад, при безпосередньому запиті до API, файлу, завантаженого користувачем, або іншого ресурсу). Можливі заходи можуть включати: не обслуговування контенту, якщо заголовки HTTP-запиту (такі як Sec-Fetch-\*) не вказують на правильний контекст; використання директиви sandbox у заголовку Content-Security-Policy; або тип attachment disposition у заголовку Content-Disposition. | 1 |
| **3.2.2** | Перевірити, що вміст, призначений для відображення як текст, а не для рендерингу як HTML, обробляється за допомогою безпечних функцій відображення (наприклад, createTextNode або textContent) для запобігання ненавмисному виконанню контенту, такого як HTML або JavaScript. | 1 |
| **3.2.3** | Перевірити, що застосунок запобігає DOM clobbering при використанні клієнтського JavaScript шляхом явного оголошення змінних, суворої перевірки типів, уникнення збереження глобальних змінних у об’єкті document та впровадження namespace isolation. | 3 |

## V3.3 Налаштування cookie

Цей розділ окреслює вимоги щодо безпечного налаштування чутливих cookies з метою забезпечення більш високого рівня впевненості, що вони створені саме самим застосунком, а також для запобігання витоку їх контенту або його неправомірній зміні.

| # | Опис | Рівень |
| :---: | :--- | :---: |
| **3.3.1** | Перевірити, що для cookies встановлено атрибут 'Secure', і якщо для імені cookie не використовується префікс '\__Host-', то обов’язково має використовуватися префікс '__Secure-'. | 1 |
| **3.3.2** | Перевірити, що значення атрибута 'SameSite' для кожного cookie встановлено відповідно до призначення цього cookie, щоб обмежити вплив атак на користувацький інтерфейс (user interface redress attacks) та браузерних атак типу підробки міжсайтових запитів (CSRF). | 2 |
| **3.3.3** | Перевірити, що cookie мають префікс '__Host-' в імені, якщо вони явно не призначені для спільного використання з іншими хостами. | 2 |
| **3.3.4** | Перевірити, що якщо значення cookie не повинно бути доступним для клієнтських скриптів (таких як токен сесії), то для такого cookie має бути встановлено атрибут 'HttpOnly', і це саме значення (наприклад, токен сесії) повинно передаватися клієнту лише через заголовок 'Set-Cookie'. | 2 |
| **3.3.5** | Перевірити, що при записі cookie сумарна довжина імені та значення cookie не перевищує 4096 байтів. Надто великі cookie не зберігатимуться браузером і, відповідно, не надсилатимуться із запитами, що призведе до неможливості користування функціоналом застосунку, який залежить від цього cookie. | 3 |

## V3.4 Browser Security Mechanism Headers

This section describes which security headers should be set on HTTP responses to enable browser security features and restrictions when handling responses from the application.

| # | Description | Level |
| :---: | :--- | :---: |
| **3.4.1** | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | 1 |
| **3.4.2** | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | 1 |
| **3.4.3** | Verify that HTTP responses include a Content-Security-Policy response header field which defines directives to ensure the browser only loads and executes trusted content or resources, in order to limit execution of malicious JavaScript. As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes. For an L3 application, a per-response policy with nonces or hashes must be defined. | 2 |
| **3.4.4** | Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. This instructs browsers not to use content sniffing and MIME type guessing for the given response, and to require the response's Content-Type header field value to match the destination resource. For example, the response to a request for a style is only accepted if the response's Content-Type is 'text/css'. This also enables the use of the Cross-Origin Read Blocking (CORB) functionality by the browser. | 2 |
| **3.4.5** | Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the 'Referer' HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname. | 2 |
| **3.4.6** | Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response to ensure that it cannot be embedded by default and that embedding of specific resources is allowed only when necessary. Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon. | 2 |
| **3.4.7** | Verify that the Content-Security-Policy header field specifies a location to report violations. | 3 |
| **3.4.8** | Verify that all HTTP responses that initiate a document rendering (such as responses with Content-Type text/html), include the Cross‑Origin‑Opener‑Policy header field with the same-origin directive or the same-origin-allow-popups directive as required. This prevents attacks that abuse shared access to Window objects, such as tabnabbing and frame counting. | 3 |

## V3.5 Browser Origin Separation

When accepting a request to sensitive functionality on the server side, the application needs to ensure the request is initiated by the application itself or by a trusted party and has not been forged by an attacker.

Sensitive functionality in this context could include accepting form posts for authenticated and non-authenticated users (such as an authentication request), state-changing operations, or resource-demanding functionality (such as data export).

The key protections here are browser security policies like Same Origin Policy for JavaScript and also SameSite logic for cookies. Another common protection is the CORS preflight mechanism. This mechanism will be critical for endpoints designed to be called from a different origin, but it can also be a useful request forgery prevention mechanism for endpoints which are not designed to be called from a different origin.

| # | Description | Level |
| :---: | :--- | :---: |
| **3.5.1** | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | 1 |
| **3.5.2** | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | 1 |
| **3.5.3** | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | 1 |
| **3.5.4** | Verify that separate applications are hosted on different hostnames to leverage the restrictions provided by same-origin policy, including how documents or scripts loaded by one origin can interact with resources from another origin and hostname-based restrictions on cookies. | 2 |
| **3.5.5** | Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid. | 2 |
| **3.5.6** | Verify that JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion (XSSI) attacks. | 3 |
| **3.5.7** | Verify that data requiring authorization is not included in script resource responses, like JavaScript files, to prevent Cross-Site Script Inclusion (XSSI) attacks. | 3 |
| **3.5.8** | Verify that authenticated resources (such as images, videos, scripts, and other documents) can be loaded or embedded on behalf of the user only when intended. This can be accomplished by strict validation of the Sec-Fetch-* HTTP request header fields to ensure that the request did not originate from an inappropriate cross-origin call, or by setting a restrictive Cross-Origin-Resource-Policy HTTP response header field to instruct the browser to block returned content. | 3 |

## V3.6 External Resource Integrity

This section provides guidance for the safe hosting of content on third-party sites.

| # | Description | Level |
| :---: | :--- | :---: |
| **3.6.1** | Verify that client-side assets, such as JavaScript libraries, CSS, or web fonts, are only hosted externally (e.g., on a Content Delivery Network) if the resource is static and versioned and Subresource Integrity (SRI) is used to validate the integrity of the asset. If this is not possible, there should be a documented security decision to justify this for each resource. | 3 |

## V3.7 Other Browser Security Considerations

This section includes various other security controls and modern browser security features required for client-side browser security.

| # | Description | Level |
| :---: | :--- | :---: |
| **3.7.1** | Verify that the application only uses client-side technologies which are still supported and considered secure. Examples of technologies which do not meet this requirement include NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets. | 2 |
| **3.7.2** | Verify that the application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist. | 2 |
| **3.7.3** | Verify that the application shows a notification when the user is being redirected to a URL outside of the application's control, with an option to cancel the navigation. | 3 |
| **3.7.4** | Verify that the application's top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict Transport Security (HSTS). This ensures that the use of TLS for the application is built directly into the main browsers, rather than relying only on the Strict-Transport-Security response header field. | 3 |
| **3.7.5** | Verify that the application behaves as documented (such as warning the user or blocking access) if the browser used to access the application does not support the expected security features. | 3 |

## References

For more information, see also:

* [Set-Cookie __Host- prefix details](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes)
* [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
* [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* [HSTS Browser Preload List submission form](https://hstspreload.org/)
* [OWASP DOM Clobbering Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html)
