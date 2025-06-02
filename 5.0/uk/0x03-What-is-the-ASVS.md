# Що таке ASVS?

Стандарт верифікації вимог до безпеки застосунків (ASVS) визначає вимоги до безпеки веб-застосунків і сервісів та є цінним ресурсом для всіх, хто прагне проєктувати, розробляти, підтримувати безпечні застосунки або оцінювати їхню безпеку.

Цей розділ описує основні аспекти використання ASVS, зокрема його сферу застосування, структуру рівнів пріоритетності та основні сценарії використання стандарту.

## Область застосування ASVS

Область застосування ASVS визначається його назвою: Застосунок, Безпека, Верифікація та Стандарт. Вона встановлює, які вимоги включено або виключено, із всеохопною метою визначення принципів безпеки, яких необхідно досягти. Область також охоплює вимоги до документації, які є основою для впровадження заходів безпеки.

Для зловмисників не існує поняття сфери застосування. Тому вимоги Стандарту верифікації вимог до безпеки застосунків (ASVS) слід оцінювати разом із рекомендаціями щодо інших аспектів життєвого циклу застосунку, зокрема процесів CI/CD, хостингу та операційної діяльності.

### Застосунок

ASVS визначає "застосунок" як програмний продукт, що розробляється, у який мають бути інтегровані контрольні заходи безпеки. ASVS не встановлює вимог щодо процесів життєвого циклу розробки і не регламентує, як саме слід будувати застосунок за допомогою CI/CD; натомість він визначає результати безпеки, яких необхідно досягти безпосередньо в самому продукті.

Компоненти, що обслуговують, модифікують або перевіряють HTTP-трафік, такі як Веб-застосункові брандмауери (WAFs), балансувальники навантаження або проксі-сервери, можуть вважатися частиною застосунку для відповідних цілей, оскільки деякі контрольні заходи безпеки безпосередньо залежать від них або можуть реалізовуватися за їх допомогою. Ці компоненти слід враховувати під час виконання вимог, пов’язаних із кешованими відповідями, обмеженням кількості запитів або обмеження вхідних і вихідних з’єднань залежно від джерела та призначення.

Натомість, ASVS зазвичай не охоплює вимоги, що не стосуються безпосередньо самого застосунку або належать до конфігурації, яка виходить за межі його відповідальності. Наприклад, аспекти, пов’язані з DNS, зазвичай належать до відповідальності іншої команди чи функції.

Як і в попередньому випадку, хоча застосунок відповідає за обробку вхідних даних і формування вихідних, взаємодія зовнішніх процесів із самим застосунком або його даними вважається поза межами сфери дії ASVS.
Наприклад, резервне копіювання застосунку або його даних зазвичай виконується зовнішнім процесом і не контролюється самим застосунком або його розробниками.

### Безпека

Кожна вимога має мати доказовий вплив на безпеку. Відсутність такої вимоги має призводити до зниження рівня безпеки застосунку, а її впровадження такої вимоги має зменшувати ймовірність або ступінь впливу ризику безпеки.

Усі інші фактори, такі як функціональні аспекти, стиль коду чи вимоги політики, не розглядаються у межах цього стандарту.

### Верифікація

Вимога має бути перевірною, а результат перевірки повинен має бути "пройшов" або "не пройшов".

### Стандарт

ASVS розроблено як збірку вимог безпеки, які необхідно реалізувати для відповідності стандарту. Це означає, що вимоги обмежуються визначенням цілі безпеки, яку потрібно досягти. Іншу пов’язану інформацію можна створювати на основі ASVS або пов’язувати через відповідності (mapping).

Конкретно, OWASP має багато проєктів, і ASVS свідомо уникає дублювання з матеріалами інших проєктів. Наприклад, розробники можуть запитувати: "Як реалізувати певну вимогу у моїй конкретній технології чи середовищі?" — на це питання має відповідати проєкт Cheat Sheet Series. Перевіряльники можуть питати: "Як протестувати цю вимогу в цьому середовищі?" — відповідь на це має міститися в проєкті Web Security Testing Guide.

Хоча ASVS призначений не лише для експертів із безпеки, він передбачає, що читач має технічні знання для розуміння змісту або здатність досліджувати окремі поняття.

### Вимога

Слово вимога в ASVS вживається у вузькому значенні, оскільки воно описує те, чого необхідно досягти, щоб її виконати. ASVS містить лише вимоги (must) і не містить рекомендацій (should) як основної умови.

Іншими словами, рекомендації, незалежно від того чи є вони лише одним із багатьох можливих варіантів розв’язання проблеми або стосуються стилю коду, не відповідають визначенню вимоги.

Вимоги ASVS спрямовані на відображення конкретних принципів безпеки без надмірної прив’язки до реалізації чи технологій, водночас залишаючись самодостатніми й зрозумілими щодо своєї мети. Це також означає, що вимоги не орієнтовані на певний метод перевірки чи спосіб реалізації.

### Задокументовані рішення щодо реалізації безпеки

У сфері безпеки програмного забезпечення, завчасне планування архітектури безпеки та механізмів, які будуть використовуватись, забезпечує більш послідовну й надійну реалізацію у кінцевому продукті або функціоналі.

Крім того, для деяких вимог реалізація може бути складною та дуже специфічною для потреб конкретного застосунку. Типовими прикладами є дозволи, перевірка вхідних даних та захисні механізми навколо різних рівнів конфіденційних даних.

Щоб врахувати це, замість загальних заяв на кшталт "всі дані мають бути зашифровані" або спроб охопити кожен можливий випадок використання у вимозі, були включені вимоги до документації, які зобов’язують розробника застосунку документувати свій підхід та налаштування таких контролів. Це потім може бути перевірено на відповідність, а фактичну реалізацію порівняно з документацією, щоб оцінити, чи відповідає реалізація очікуванням.

Ці вимоги призначені для документування рішень, які організація, що розробляє застосунок, прийняла щодо способів впровадження певних вимог безпеки.

Вимоги до документації завжди розміщуються у першому розділі глави (хоча не в кожній главі вони присутні) і завжди мають відповідну вимогу до впровадження, згідно з якою задокументовані рішення мають бути реально втілені. Сутність полягає в тому, що перевірка наявності документації та перевірка фактичного впровадження це два окремі процеси.

Існує два основні чинники, що зумовлюють включення цих вимог. Перший чинник полягає в тому, що вимога безпеки часто передбачає застосування певних правил, наприклад, які типи файлів дозволено завантажувати, які бізнес-контролі потрібно впровадити, які символи дозволені у певному полі. Ці правила відрізняються для кожного застосунку, тому ASVS не може однозначно визначати, якими вони мають бути, і навіть чек-лист або детальніші рекомендації не допоможуть у цьому випадку. Аналогічно, без документування таких рішень неможливо буде провести перевірку вимог, що реалізують ці рішення.

Другий чинник полягає в тому, що для певних вимог важливо надати розробникам застосунків гнучкість у виборі способів вирішення конкретних питань безпеки. Наприклад, у попередніх версіях ASVS правила тайм-ауту сесій були дуже жорсткими. Практично ж, багато застосунків, особливо ті, які орієнтовані на кінцевого користувача, застосовують більш пом’якшені правила і віддають перевагу впровадженню інших заходів пом’якшення ризиків. Відповідні вимоги до документації, таким чином, явно передбачають таку гнучкість.

Очевидно, що прийняття та документування таких рішень не очікується від окремих розробників, а здійснюється організацією в цілому, яка відповідально приймає ці рішення та забезпечує їх донесення до розробників, які, у свою чергу, мають дотримуватися встановлених вимог.

Надання розробникам специфікацій та проєктувань для нових функцій і можливостей є стандартною частиною розробки програмного забезпечення. Аналогічно, від розробників очікується використання загальних компонентів і механізмів користувацького інтерфейсу, а не щоращу прийняття власних рішень. Таким чином, поширення цього підходу на сферу безпеки не має викликати здивування чи суперечностей.

Існує також гнучкість у способах досягнення цього. Рішення з безпеки можуть бути задокументовані у вигляді письмового документа, на який розробники повинні посилатися. Альтернативою є те, що рішення з безпеки можуть бути задокументовані та реалізовані у спільній бібліотеці коду, яку всі розробники зобов’язані використовувати. В обох випадках досягається бажаний результат.

## Рівні верифікації вимог до безпеки застосунків

ASVS визначає три рівні верифікації безпеки, кожен з яких відрізняється глибиною та складністю. Загальна мета полягає в тому, щоб організації починали з першого рівня для усунення найбільш критичних питань безпеки, а згодом переходили до вищих рівнів відповідно до потреб організації та застосунку. У документі та текстах вимог рівні можуть позначатися як L1, L2 та L3.

Кожен рівень ASVS визначає вимоги до безпеки, які необхідно досягнути на цьому рівні, при цьому вимоги вищих рівнів вважаються рекомендаціями.

Щоб уникнути дублювання вимог або вимог, які вже не є релевантними на вищих рівнях, деякі вимоги застосовуються до конкретного рівня, але на вищих рівнях мають більш жорсткі умови.

### Level evaluation

Levels are defined by priority-based evaluation of each requirement based on experience implementing and testing security requirements. The main focus is on comparing risk reduction with the effort to implement the requirement. Another key factor is to keep a low barrier to entry.

Risk reduction considers the extent to which the requirement reduces the level of security risk within the application, taking into account the classic Confidentiality, Integrity, and Availability impact factors as well as considering whether this is a primary layer of defense or whether it would be considered defense in depth.

The rigorous discussions around both the criteria and the leveling decisions have resulted in an allocation which should hold true for the vast majority of cases, whilst accepting that it may not be a 100% fit for every situation. This means that in certain cases, organizations may wish to prioritize requirements from a higher level earlier on based on their own specific risk considerations.

The types of requirements in each level could be characterized as follows.

### Level 1

This level contains the minimum requirements to consider when securing an application and represents a critical starting point. This level contains around 20% of the ASVS requirements. The goal for this level is to have as few requirements as possible, to decrease the barrier to entry.

These requirements are generally critical or basic, first-layer of defense requirements for preventing common attacks that do not require other vulnerabilities or preconditions to be exploitable.

In addition to the first layer of defense requirements, some requirements have less of an impact at higher levels, such as requirements related to passwords. Those are more important for Level 1, as from higher levels, the multi-factor authentication requirements become relevant.

Level 1 is not necessarily penetration testable by an external tester without internal access to documentation or code (such as "black box" testing), although the lower number of requirements should make it easier to verify.

### Level 2

Most applications should be striving to achieve this level of security. Around 50% of the requirements in the ASVS are L2 meaning that an application needs to implement around 70% of the requirements in the ASVS (all of the L1 and L2 requirements) in order to comply with L2.

These requirements generally relate to either less common attacks or more complicated protections against common attacks. They may still be a first layer of defense, or they may require certain preconditions for the attack to be successful.

### Level 3

This level should be the goal for applications looking to demonstrate the highest levels of security and provides the final ~30% of requirements to comply with.

Requirements in this section are generally either defense-in-depth mechanisms or other useful but hard-to-implement controls.

### Which level to achieve

The priority-based levels are intended to provide a reflection of the application security maturity of the organization and the application. Rather than the ASVS prescriptively stating what level an application should be at, an organization should analyze its risks and decide what level it believes it should be at, depending on the sensitivity of the application and of course, the expectations of the application's users.

For example, an early-stage startup that is only collecting limited sensitive data may decide to focus on Level 1 for its initial security goals, but a bank may have difficulty justifying anything less than Level 3 to its customers for its online banking application.

## How to use the ASVS

### The structure of the ASVS

The ASVS is made up of a total of around 350 requirements which are divided into 17 chapters, each of which is further divided into sections.

The aim of the chapter and section division is to simplify choosing or filtering out chapters and sections based on the what is relevant for the application. For example, for a machine-to-machine API, the requirements in chapter V3 related to web frontends will not be relevant. If there is no use of OAuth or WebRTC, then those chapters can be ignored as well.

### Release strategy

ASVS releases follow the pattern "Major.Minor.Patch" and the numbers provide information on what has changed within the release. In a major release, the first number will change, in a minor release, the second number will change, and in a patch release, the third number will change.

* Major release - Full reorganization, almost everything may have changed, including requirement numbers. Reevaluation for compliance will be necessary (for example, 4.0.3 -> 5.0.0).
* Minor release - Requirements may be added or removed, but overall numbering will stay the same. Reevaluation for compliance will be necessary, but should be easier (for example, 5.0.0 -> 5.1.0).
* Patch release - Requirements may be removed (for example, if they are duplicates or outdated) or made less stringent, but an application that complied with the previous release will comply with the patch release as well (for example, 5.0.0 -> 5.0.1).

The above specifically relates to the requirements in the ASVS. Changes to surrounding text and other content such as the appendices will not be considered to be a breaking change.

### Flexibility with the ASVS

Several of the points described above, such as documentation requirements and the levels mechanism, provide the ability to use the ASVS in a more flexible and organization-specific way.

Additionally, organizations are strongly encouraged to create an organization- or domain-specific fork that adjusts requirements based on the specific characteristics and risk levels of their applications. However, it is important to maintain traceability so that passing requirement 4.1.1 means the same across all versions.

Ideally, each organization should create its own tailored ASVS, omitting irrelevant sections (e.g., GraphQL, WebSockets, SOAP, if unused). An organization-specific ASVS version or supplement is also a good place to provide organization-specific implementation guidance, detailing libraries or resources to use when complying with requirements.

### How to Reference ASVS Requirements

Each requirement has an identifier in the format `<chapter>.<section>.<requirement>`, where each element is a number. For example, `1.11.3`.

* The `<chapter>` value corresponds to the chapter from which the requirement comes; for example, all `1.#.#` requirements are from the 'Encoding and Sanitization' chapter.
* The `<section>` value corresponds to the section within that chapter where the requirement appears, for example: all `1.2.#` requirements are in the 'Injection Prevention' section of the 'Encoding and Sanitization' chapter.
* The `<requirement>` value identifies the specific requirement within the chapter and section, for example, `1.2.5` which as of version 5.0.0 of this standard is:

> Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding.

Since the identifiers may change between versions of the standard, it is preferable for other documents, reports, or tools to use the following format: `v<version>-<chapter>.<section>.<requirement>`, where: 'version' is the ASVS version tag. For example: `v5.0.0-1.2.5` would be understood to mean specifically the 5th requirement in the 'Injection Prevention' section of the 'Encoding and Sanitization' chapter from version 5.0.0. (This could be summarized as `v<version>-<requirement_identifier>`.)

Note: The `v` preceding the version number in the format should always be lowercase.

If identifiers are used without including the `v<version>` element then they should be assumed to refer to the latest Application Security Verification Standard content. As the standard grows and changes this becomes problematic, which is why writers or developers should include the version element.

ASVS requirement lists are made available in CSV, JSON, and other formats which may be useful for reference or programmatic use.

### Forking the ASVS

Organizations can benefit from adopting ASVS by choosing one of the three levels or by creating a domain-specific fork that adjusts requirements per application risk level. This type of fork is encouraged, provided that it maintains traceability so that passing requirement 4.1.1 means the same across all versions.

Ideally, each organization should create its own tailored ASVS, omitting irrelevant sections (e.g., GraphQL, Websockets, SOAP, if unused). Forking should start with ASVS Level 1 as a baseline, advancing to Levels 2 or 3 based on the application’s risk.

## Use cases for the ASVS

The ASVS can be used to assess the security of an application and this is explored in more depth in the next chapter. However, several other potential uses for the ASVS (or a forked version) have been identified.

### As Detailed Security Architecture Guidance

One of the more common uses for the Application Security Verification Standard is as a resource for security architects. There are limited resources available for how to build a secure application archiecture, especially with modern applications. ASVS can be used to fill in those gaps by allowing security architects to choose better controls for common problems, such as data protection patterns and input validation strategies. The architecture and documentation requirements will be particularly useful for this.

### As a Specialized Secure Coding Reference

The ASVS can be used as a basis for preparing a secure coding reference during application development, helping developers to make sure that they keep security in mind when they build software. Whilst the ASVS can be the base, prganizations should prepare their own specific guidance which is clear and unified and ideally be prepared based on guidance from security engineers or security architects. As an extension to this, organizations are encouraged wherever possible to prepare approved security mechanisms and libraries that can be referenced in the guidance and used by developers.

### As a Guide for Automated Unit and Integration Tests

The ASVS is designed to be highly testable. Some verifications will be technical where as other requirements (such as the architectural and documentation requirements) may require documentation or architecture review. By building unit and integration tests that test and fuzz for specific and relevant abuse cases related to the requirements that are verifiable by technical means, it should be easier to check that these controls are operating correctly on each build. For example, additional tests can be crafted for the test suite for a login controller, testing the username parameter for common default usernames, account enumeration, brute forcing, LDAP and SQL injection, and XSS. Similarly, a test on the password parameter should include common passwords, password length, null byte injection, removing the parameter, XSS, and more.

### For Secure Development Training

ASVS can also be used to define the characteristics of secure software. Many “secure coding” courses are simply ethical hacking courses with a light smear of coding tips. This may not necessarily help developers to write more secure code. Instead, secure development courses can use the ASVS with a strong focus on the positive mechanisms found in the ASVS, rather than the Top 10 negative things not to do. The ASVS structure also provides a logical structure for walking through the different topics when securing an application.

### As a Framework for Guiding the Procurement of Secure Software

The ASVS is a great framework to help with secure software procurement or procurement of custom development services. The buyer can simply set a requirement that the software they wish to procure must be developed at ASVS level X, and request that the seller proves that the software satisfies ASVS level X.

## Applying ASVS in Practice

Different threats have different motivations. Some industries have unique information and technology assets and domain-specific regulatory compliance requirements.

Organizations are strongly encouraged to look deeply at their unique risk characteristics based on the nature of their business, and based upon that risk and business requirements determine the appropriate ASVS level.
