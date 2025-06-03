# V2 Валідація та бізнес-логіка

## Мета контролю

Цей розділ має на меті забезпечити, щоб перевірений застосунок відповідав наступним високорівневим цілям:

* Вхідні дані, що надходять до застосунку, відповідають бізнесовим або функціональним очікуванням.
* Потік бізнес-логіки є послідовним, обробляється у визначеному порядку та не може бути обійдений.
* Бізнес-логіка містить обмеження та контролі для виявлення та запобігання автоматизованим атакам, таким як безперервні малі перекази коштів або додавання мільйона друзів по одному.
* Потоки бізнес-логіки з високою цінністю враховують випадки зловживань і зловмисників, а також мають захист від підробки, фальсифікацій, розкриття інформації та атак на підвищення привілеїв.

## V2.1 Документація з валідації та бізнес-логіки

Документація з валідації та бізнес-логіки повинна чітко визначати межі бізнес-логіки, правила валідації та контекстну узгодженість поєднаних даних, щоб було зрозуміло, що саме необхідно реалізувати в застосунку.

| # | Опис | Рівень |
| :---: | :--- | :---: |
| **2.1.1** | Перевірити, що документація застосунку визначає правила валідації вхідних даних для перевірки їх відповідності очікуваній структурі. Це можуть бути загальні формати даних, такі як номери кредитних карток, електронні адреси, номери телефонів, або ж внутрішній формат даних. | 1 |
| **2.1.2** | Перевірити, що документація застосунку визначає, як здійснювати перевірку логічної та контекстної узгодженості поєднаних даних, наприклад, перевірку відповідності між назвою передмістя (suburb) та поштовим індексом (ZIP код). | 2 |
| **2.1.3** | Перевірити, що очікування щодо меж бізнес-логіки та правил валідації задокументовані, включно з вимогами як на рівні окремого користувача, так і на глобальному рівні застосунку. | 2 |

## V2.2 Input Validation

Effective input validation controls enforce business or functional expectations around the type of data the application expects to receive. This ensures good data quality and reduces the attack surface. However, it does not remove or replace the need to use correct encoding, parameterization, or sanitization when using the data in another component or for presenting it for output.

In this context, "input" could come from a wide variety of sources, including HTML form fields, REST requests, URL parameters, HTTP header fields, cookies, files on disk, databases, and external APIs.

A business logic control might check that a particular input is a number less than 100. A functional expectation might check that a number is below a certain threshold, as that number controls how many times a particular loop will take place, and a high number could lead to excessive processing and a potential denial of service condition.

While schema validation is not explicitly mandated, it may be the most effective mechanism for full validation coverage of HTTP APIs or other interfaces that use JSON or XML.

Please note the following points on Schema Validation:

* The "published version" of the JSON Schema validation specification is considered production-ready, but not strictly speaking "stable." When using JSON Schema validation, ensure there are no gaps with the guidance in the requirements below.
* Any JSON Schema validation libraries in use should also be monitored and updated if necessary once the standard is formalized.
* DTD validation should not be used, and framework DTD evaluation should be disabled, to avoid issues with XXE attacks against DTDs.

| # | Description | Level |
| :---: | :--- | :---: |
| **2.2.1** | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | 1 |
| **2.2.2** | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | 1 |
| **2.2.3** | Verify that the application ensures that combinations of related data items are reasonable according to the pre-defined rules. | 2 |

## V2.3 Business Logic Security

This section considers key requirements to ensure that the application enforces business logic processes in the correct way and is not vulnerable to attacks that exploit the logic and flow of the application.

| # | Description | Level |
| :---: | :--- | :---: |
| **2.3.1** | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | 1 |
| **2.3.2** | Verify that business logic limits are implemented per the application's documentation to avoid business logic flaws being exploited. | 2 |
| **2.3.3** | Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state. | 2 |
| **2.3.4** | Verify that business logic level locking mechanisms are used to ensure that limited quantity resources (such as theater seats or delivery slots) cannot be double-booked by manipulating the application's logic. | 2 |
| **2.3.5** | Verify that high-value business logic flows require multi-user approval to prevent unauthorized or accidental actions. This could include but is not limited to large monetary transfers, contract approvals, access to classified information, or safety overrides in manufacturing. | 3 |

## V2.4 Anti-automation

This section includes anti-automation controls to ensure that human-like interactions are required and excessive automated requests are prevented.

| # | Description | Level |
| :---: | :--- | :---: |
| **2.4.1** | Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage-data creation, quota exhaustion, rate-limit breaches, denial-of-service, or overuse of costly resources. | 2 |
| **2.4.2** | Verify that business logic flows require realistic human timing, preventing excessively rapid transaction submissions. | 3 |

## References

For more information, see also:

* [OWASP Web Security Testing Guide: Input Validation Testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README.html)
* [OWASP Web Security Testing Guide: Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README)
* Anti-automation can be achieved in many ways, including the use of the [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
* [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
* [JSON Schema](https://json-schema.org/specification.html)
