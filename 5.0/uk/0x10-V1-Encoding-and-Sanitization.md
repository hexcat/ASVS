# V1 Кодування та Санітизація

## Мета контролю

Цей розділ охоплює найпоширеніші вразливості безпеки веб-застосунків, пов’язані з небезпечним опрацюванням недовірених даних. Такі вразливості можуть призводити до різноманітних технічних вразливостей, коли недовірені дані інтерпретуються відповідно до синтаксичних правил відповідного інтерпретатора.

Для сучасних веб-застосунків найкраще використовувати безпечні API, такі як параметризовані запити, автоматичне екранування або шаблонізовані фреймворки. В іншому випадку критичною для безпеки застосунку стає ретельна обробка вихідних даних: кодування, екранування або санітизація.

Валідація вхідних даних слугує механізмом багатошарового захисту для запобігання небажаному або шкідливому вмісту. Однак, оскільки її основна мета це забезпечити відповідність вхідного контенту функціональним та бізнес-вимогам, відповідні вимоги  які охоплюють цей аспект, наведені у розділі "Валідація та бізнес-логіка".

## V1.1 Архітектура кодування та санітизації

У наведених нижче розділах представлені вимоги, специфічні для певного синтаксису або інтерпретатора, щодо безпечної обробки небезпечного вмісту з метою уникнення вразливостей. Вимоги цієї секції охоплюють порядок, у якому має відбуватися така обробка, а також місце її виконання. Вони також спрямовані на забезпечення, що дані під час зберігання залишалися у своєму початковому вигляді і не зберігалися у закодованій чи екранірованій формі (наприклад, у вигляді HTML-кодування), щоб уникнути проблем з подвійним кодуванням.

| # | Опис | Рівень |
| :---: | :--- | :---: |
| **1.1.1** | Перевірити, що вхідні дані декодуються або розекрановуються у канонічну форму лише один раз, декодування відбувається лише тоді, коли очікуються закодовані дані у цій формі, і що це виконується до подальшої обробки вхідних даних, зокрема не після валідації чи санітизації вхідних даних. | 2 |
| **1.1.2** | Перевірити, що застосунок виконує кодування та екранування вихідних даних або як фінальний крок перед використанням інтерпретатором, для якого вони призначені, або безпосередньо самим інтерпретатором. | 2 |

## V1.2 Запобігання ін’єкціям

Кодування або екранування вихідних даних, виконувані безпосередньо в контексті, де існує потенційна загроза, є критично важливими для безпеки будь-якого застосунку. Зазвичай кодування та екранування не зберігаються, а застосовуються безпосередньо перед відображенням, щоб зробити вміст безпечним і готовим до негайного використання відповідним інтерпретатором. Занадто раннє виконання цих операцій може призвести до пошкодження контенту або зробити кодування чи екранування неефективними.

Часто програмні бібліотеки містять безпечні або більш безпечні функції, які виконують це автоматично, проте необхідно переконатися, що вони правильно працюють у поточному контексті.

| # | Опис | Рівень |
| :---: | :--- | :---: |
| **1.2.1** | Перевірити, що кодування вихідних даних для HTTP-відповіді, HTML-документа або XML-документа відповідає необхідному контексту, такому як кодування відповідних символів для HTML-елементів, атрибутів HTML, HTML-коментарів, CSS або полів HTTP-заголовків, щоб уникнути зміни повідомлення або структури документа. | 1 |
| **1.2.2** | Перевірити, що при динамічному формуванні URL-адрес недовірені дані кодуються відповідно до їх контексту (наприклад, URL-кодування або base64url-кодування для параметрів запиту чи шляху). Забезпечити, щоб дозволялися лише безпечні протоколи URL (наприклад, заборонити javascript: або data:). | 1 |
| **1.2.3** | Перевірити, що кодування або екранування вихідних даних застосовується при динамічному формуванні JavaScript-вмісту (включно з JSON), щоб уникнути зміни структури повідомлення чи документа (щоб запобігти JavaScript- та JSON-ін’єкціям). | 1 |
| **1.2.4** | Перевірити, що для вибірки даних або запитів до бази даних (наприклад, SQL, HQL, NoSQL, Cypher) використовуються параметризовані запити, ORM, entity Frameworks або інші методи захисту від SQL-ін’єкцій та інших атак на бази даних. Це також стосується написання збережених процедур. | 1 |
| **1.2.5** | Перевірити, що застосунок захищений від OS command injection та що виклики операційної системи здійснюються із використанням параметризованих запитів ОС або контекстного кодування виводу командного рядка. | 1 |
| **1.2.6** | Перевірити, що застосунок захищений від вразливостей LDAP-ін’єкції або що впроваджені конкретні заходи безпеки для запобігання LDAP-ін’єкції. | 2 |
| **1.2.7** | Перевірити, що застосунок захищений від атак XPath-ін’єкції шляхом використання параметризованих або попередньокомпільованих запитів. | 2 |
| **1.2.8** | Перевірити, що LaTeX-процесори налаштовані безпечно (наприклад, без використання прапорця "--shell-escape") та використовується список дозволених команд для запобігання атакам типу LaTeX-ін’єкції. | 2 |
| **1.2.9** | Перевірити, що застосунок екранує спеціальні символи в регулярних виразах (зазвичай за допомогою зворотного слеша), щоб запобігти їх некоректній інтерпретації як метасимволів. | 2 |
| **1.2.10** | Перевірити, що застосунок захищений від CSV-ін’єкцій та ін’єкцій формул. Застосунок повинен дотримуватися правил екранування, визначених у розділах 2.6 і 2.7 RFC 4180 під час експорту у формат CSV. Крім того, при експорті у CSV або інші табличні формати (наприклад, XLS, XLSX, ODF) спеціальні символи (включно з '=', '+', '-', '@', '\t' (табуляція) та '\0' (нульовий символ)) повинні екрануватися одинарною лапкою, якщо вони є першим символом у значенні поля. | 3 |

Примітка: Використання параметризованих запитів або екранування SQL не завжди є достатнім. Частини запиту, такі як імена таблиць і стовпців (включно з іменами стовпців у "ORDER BY"), не можуть бути екрановані. Якщо у цих полях використовувати екрановані дані, отримані від користувача, це призведе до помилок у запитах або SQL-ін’єкцій.

## V1.3 Санітизація

Ідеальним захистом від використання недовіреного контенту у небезпечному контексті є застосування контекстно-залежного кодування або екранування, яке зберігає семантичне значення таких даних, але робить їх безпечними для використання саме в цьому контексті, що детальніше описано у попередньому розділі.

Якщо це неможливо, тоді необхідна санітизація, видалення потенційно небезпечних символів або контенту. У деяких випадках це може змінити семантичне значення вхідних даних, але з міркувань безпеки альтернативи може не бути.

| # | Опис | Рівень |
| :---: | :--- | :---: |
| **1.3.1** | Перевірити, що весь недовірений HTML-вміст із WYSIWYG редакторів або подібних джерел санітизується з використанням відомої та безпечної бібліотеки або особливостей фреймворку для санітизації HTML. | 1 |
| **1.3.2** | Перевірити, що застосунок уникає використання eval() або інших засобів динамічного виконання коду, таких як Spring Expression Language (SpEL). Якщо іншого варіанту немає, будь-які користувацькі дані, які включені до виконання, мають бути санітизовані перед виконанням. | 1 |
| **1.3.3** | Перевірити, що дані, які передаються у потенційно небезпечний контекст, попередньо санітізовані для забезпечення заходів безпеки, зокрема допускати лише символи, безпечні для цього контексту, а також обрізати вхідні дані, які мають надмірну довжину. | 2 |
| **1.3.4** | Перевірити, що скриптовий контент Scalable Vector Graphics (SVG), наданий користувачем, проходить валідацію або санітизацію, щоб містити лише теги та атрибути (наприклад, для малювання графіки), які є безпечними для застосунку, зокрема не містити скриптів і foreignObject. | 2 |
| **1.3.5** | Перевірити, що застосунок очищує або вимикає скриптовий контент або контент мов виразів і шаблонів, наданий користувачем, наприклад Markdown, CSS або XSL-стилі, BBCode чи подібні. | 2 |
| **1.3.6** | Перевірити, що застосунок захищений від атак Server-side Request Forgery (SSRF) шляхом валідації ненадійних даних за списком дозволених протоколів, доменів, шляхів і портів, а також санітизація потенційно небезпечних символів перед використанням цих даних для виклику іншого сервісу. | 2 |
| **1.3.7** | Перевірити, що застосунок захищений від атак template injection, не дозволяючи створювати шаблони на основі ненадійного вводу. Якщо альтернативи немає, будь-який ненадійний ввід, який динамічно включається під час створення шаблону, повинен проходити санітизацію або сувору валідацію. | 2 |
| **1.3.8** | Перевірити, що застосунок належним чином санітизує ненадійний ввід перед використанням у запитах Java Naming and Directory Interface (JNDI) та що JNDI налаштовано безпечно для запобігання атакам JNDI injection. | 2 |
| **1.3.9** | Перевірити, що застосунок очищує контент перед відправленням у memcache для запобігання атакам ін’єкцій. | 2 |
| **1.3.10** | Перевірити, що рядки форматування, які можуть виконуватися несподіваним або зловмисним способом при використанні, проходять санітизацію перед обробкою. | 2 |
| **1.3.11** | Перевірити, що застосунок очищує користувацькі вхідні дані перед передачею до поштових систем для захисту від SMTP- або IMAP-ін’єкцій. | 2 |
| **1.3.12** | Перевірити, що регулярні вирази не містять елементів, які викликають експоненціальний backtracking, а також забезпечити очищення ненадійного вводу для зменшення ризику атак типу ReDoS або Runaway Regex. | 3 |

## V1.4 Memory, String, and Unmanaged Code

The following requirements address risks associated with unsafe memory use, which generally apply when the application uses a systems language or unmanaged code.

In some cases, it may be possible to achieve this by setting compiler flags that enable buffer overflow protections and warnings, including stack randomization and data execution prevention, and that break the build if unsafe pointer, memory, format string, integer, or string operations are found.

| # | Description | Level |
| :---: | :--- | :---: |
| **1.4.1** | Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows. | 2 |
| **1.4.2** | Verify that sign, range, and input validation techniques are used to prevent integer overflows. | 2 |
| **1.4.3** | Verify that dynamically allocated memory and resources are released, and that references or pointers to freed memory are removed or set to null to prevent dangling pointers and use-after-free vulnerabilities. | 2 |

## V1.5 Safe Deserialization

The conversion of data from a stored or transmitted representation into actual application objects (deserialization) has historically been the cause of various code injection vulnerabilities. It is important to perform this process carefully and safely to avoid these types of issues.

In particular, certain methods of deserialization have been identified by programming language or framework documentation as insecure and cannot be made safe with untrusted data. For each mechanism in use, careful due diligence should be performed.

| # | Description | Level |
| :---: | :--- | :---: |
| **1.5.1** | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | 1 |
| **1.5.2** | Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks. Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input. | 2 |
| **1.5.3** | Verify that different parsers used in the application for the same data type (e.g., JSON parsers, XML parsers, URL parsers), perform parsing in a consistent way and use the same character encoding mechanism to avoid issues such as JSON Interoperability vulnerabilities or different URI or file parsing behavior being exploited in Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks. | 3 |

## References

For more information, see also:

* [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [OWASP DOM Based Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
* [OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [OWASP Web Security Testing Guide: Client-Side Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing)
* [OWASP Java Encoding Project](https://owasp.org/owasp-java-encoder/)
* [DOMPurify - Client-side HTML Sanitization Library](https://github.com/cure53/DOMPurify)
* [RFC4180 - Common Format and MIME Type for Comma-Separated Values (CSV) Files](https://datatracker.ietf.org/doc/html/rfc4180#section-2)

For more information, specifically on deserialization or parsing issues, please see:

* [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
* [An Exploration of JSON Interoperability Vulnerabilities](https://bishopfox.com/blog/json-interoperability-vulnerabilities)
* [Orange Tsai - A New Era of SSRF Exploiting URL Parser In Trending Programming Languages](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
