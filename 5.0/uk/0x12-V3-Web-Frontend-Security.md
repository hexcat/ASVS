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
| **3.3.2** | Перевірити, що значення атрибута 'SameSite' встановлено для кожного cookie відповідно до призначення цього cookie, щоб обмежити вплив атак на користувацький інтерфейс (user interface redress attacks) та браузерних атак типу підробки міжсайтових запитів (CSRF). | 2 |
| **3.3.3** | Перевірити, що cookie мають префікс '__Host-' в імені, якщо вони явно не призначені для спільного використання з іншими хостами. | 2 |
| **3.3.4** | Перевірити, що якщо значення cookie не повинно бути доступним для клієнтських скриптів (таких як токен сесії), то для такого cookie має бути встановлено атрибут 'HttpOnly', і це саме значення (наприклад, токен сесії) повинно передаватися клієнту лише через заголовок 'Set-Cookie'. | 2 |
| **3.3.5** | Перевірити, що при записі cookie сумарна довжина імені та значення cookie не перевищує 4096 байтів. Надто великі cookie не зберігатимуться браузером і, відповідно, не надсилатимуться із запитами, що призведе до неможливості користування функціоналом застосунку, який залежить від цього cookie. | 3 |

## V3.4 Заголовки механізмів безпеки браузера

У цьому розділі описано, які заголовки безпеки слід встановлювати у HTTP-відповідях для ввімкнення механізмів безпеки браузера та обмежень під час обробки відповідей від застосунку.

| # | Опис | Рівень |
| :---: | :--- | :---: |
| **3.4.1** | Перевірити, що у всіх відповідях встановлено заголовок Strict-Transport-Security для застосування політики HTTP Strict Transport Security (HSTS). Має бути визначено максимальний термін дії, а саме не менше одного року, а для рівня L2 і вище політика повинна поширюватися також на всі піддомени. | 1 |
| **3.4.2** | Перевірити, що заголовок Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin має фіксоване значення, встановлене застосунком, або, якщо використовується значення заголовка Origin HTTP-запиту, воно проходить перевірку за списком довірених джерел. Якщо потрібно використовувати 'Access-Control-Allow-Origin: *', то перевірити, що відповідь не містить жодної конфіденційної інформації. | 1 |
| **3.4.3** | Перевірити, що HTTP-відповіді містять заголовок Content-Security-Policy, який визначає директиви, що забезпечують завантаження та виконання браузером лише довіреного контенту або ресурсів, щоб обмежити виконання шкідливого JavaScript. Мінімально має бути використана глобальна політика, яка містить директиви object-src 'none' та base-uri 'none', а також визначає список дозволених ресурсів або використовує nonces чи хеші. Для застосунку рівня L3 має бути визначена політика на кожну відповідь з використанням nonces або хешів. | 2 |
| **3.4.4** | Перевірити, що всі HTTP-відповіді містять заголовок 'X-Content-Type-Options: nosniff'. Цей заголовок вказує браузерам не використовувати content sniffing та не вгадувати MIME-тип для наданої відповіді, а вимагати, щоб значення заголовка Content-Type відповідало типу запитуваного ресурсу. Наприклад, відповідь на запит стилю приймається лише якщо Content-Type відповіді має значення 'text/css'. Це також дозволяє браузеру використовувати функціонал Cross-Origin Read Blocking (CORB). | 2 |
| **3.4.5** | Перевірити, що застосунок встановлює referrer policy для запобігання витоку технічно чутливих даних до сторонніх сервісів через заголовок HTTP-запиту 'Referer'. Це може бути зроблено через HTTP-заголовок Referrer-Policy або через атрибути HTML-елементів. Чутливі дані можуть включати шлях та параметри запиту у URL, а для внутрішніх непублічних застосунків — також ім’я хоста. | 2 |
| **3.4.6** | Перевірити, що веб-застосунок у всіх HTTP-відповідях використовує директиву frame-ancestors у заголовку Content-Security-Policy, щоб за замовчуванням заборонити вбудовування конкретних ресурсів і дозволяти їх вбудовування лише у разі необхідності. Зверніть увагу, що заголовок X-Frame-Options, хоча й підтримується браузерами, але він є застарілим  і не повинен використовуватись як основний механізм захисту. | 2 |
| **3.4.7** | Перевірити, що заголовок Content-Security-Policy вказує адресу для надсилання звітів про порушення політики. | 3 |
| **3.4.8** | Перевірити, що всі HTTP-відповіді, які ініціюють рендеринг документа (такі як відповіді з Content-Type text/html), містять заголовок Cross-Origin-Opener-Policy з директивою same-origin або same-origin-allow-popups за потребою. Це запобігає атакам, які зловживають спільним доступом до об’єктів Window, таким як tabnabbing та frame counting. | 3 |

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

## V3.6 Цілісність зовнішніх ресурсів

Ця секція містить рекомендації щодо безпечного використання контенту, розміщеного на сторонніх сайтах.

| # | Опис | Рівень |
| :---: | :--- | :---: |
| **3.6.1** | Перевірити, що клієнтські ресурси, такі як JavaScript-бібліотеки, CSS або веб-шрифти, розміщуються на зовнішніх ресурсах (наприклад, на Content Delivery Network) лише у випадку, якщо цей ресурс є статичним, має версіонування та використовує механізм перевірки цілісності підресурсів (Subresource Integrity, SRI). Якщо це неможливо, має існувати задокументоване обґрунтоване рішення з безпеки для кожного такого ресурсу. | 3 |

## V3.7 Other Browser Security Considerations

This section includes various other security controls and modern browser security features required for client-side browser security.

| # | Description | Level |
| :---: | :--- | :---: |
| **3.7.1** | Verify that the application only uses client-side technologies which are still supported and considered secure. Examples of technologies which do not meet this requirement include NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets. | 2 |
| **3.7.2** | Verify that the application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist. | 2 |
| **3.7.3** | Verify that the application shows a notification when the user is being redirected to a URL outside of the application's control, with an option to cancel the navigation. | 3 |
| **3.7.4** | Verify that the application's top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict Transport Security (HSTS). This ensures that the use of TLS for the application is built directly into the main browsers, rather than relying only on the Strict-Transport-Security response header field. | 3 |
| **3.7.5** | Verify that the application behaves as documented (such as warning the user or blocking access) if the browser used to access the application does not support the expected security features. | 3 |

## Посилання

Для додаткової інформації дивіться також:

* [Set-Cookie __Host- prefix details](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes)
* [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
* [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* [HSTS Browser Preload List submission form](https://hstspreload.org/)
* [OWASP DOM Clobbering Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html)
