# Зміни порівняно з версією 4.x

## Вступ

Користувачам, знайомим із 4.x версією стандарту, може бути корисно ознайомитися з основними змінами, запровадженими у версії 5.0, зокрема оновленнями змісту, скоупу та базової філософії.

З 286 вимог, що містилися у версії 4.0.3, лише 11 залишилися без змін, ще 15 зазнали незначних граматичних коригувань без впливу на зміст. Загалом 109 вимог (38 %) більше не представлені як окремі у версії 5.0: 50 було просто вилучено, 28 усунуто як дублікати, а 31 об’єднано з іншими вимогами. Решта були переглянуті у тій чи іншій формі. Навіть ті вимоги, які не були суттєво змінені, мають нові ідентифікатори через оновлену структуру або порядок.

Для полегшення переходу на версію 5.0 надаються документи зіставлення, що допомагають простежити відповідність між вимогами версій 4.x та 5.0. Ці зіставлення не є жорстко прив’язаними до конкретних релізів і можуть оновлюватися або уточнюватися за потреби.

## Філософія вимог

### Скоуп та фокус

У версії 4.x були присутні вимоги, що не відповідали передбаченому скоупом стандарту; їх було вилучено. Також були виключені вимоги, які не відповідали критеріям скоупу для версії 5.0 або не підлягали перевірці.

### Акцент на цілях безпеки, а не на механізмах

У версії 4.x багато вимог були зосереджені на конкретних механізмах замість того, щоб бути орієнтованими на основні цілі безпеки. У версії 5.0 вимоги побудовані навколо саме цілей безпеки; конкретні механізми згадуються лише у випадках, коли вони є єдиним практичним рішенням, або подаються як приклади чи додаткові рекомендації.

Такий підхід визнає, що існує кілька способів досягнення певної цілі безпеки, й уникає зайвої нормативності, яка могла б обмежити гнучкість організацій.

Також були об’єднані вимоги, що стосуються однієї й тієї ж проблеми безпеки, де це було доцільно.

### Документовані рішення у сфері безпеки

Хоча концепція документованих рішень у сфері безпеки може здатися новою у версії 5.0, вона є логічним продовженням попередніх вимог, пов’язаних із застосуванням політик і моделюванням загроз у версії 4.0. Раніше деякі вимоги неявно передбачали проведення аналізу для обґрунтування впровадження механізмів захисту таких як, визначення допустимих мережевих з’єднань.

Щоб забезпечити наявність необхідної інформації для впровадження та верифікації, ці очікування тепер чітко визначені як вимоги до документації, що робить їх прозорими, практичними та такими, що піддаються перевірці.

## Структурні зміни та нові розділи

У версії 5.0 додано кілька розділів із повністю новим змістом:

* OAuth та OIDC – з огляду на широке впровадження цих протоколів для делегування доступу та єдиного входу (SSO), додано окремі вимоги, які охоплюють різноманітні сценарії, з якими можуть стикатися розробники. У перспективі цей розділ може еволюціонувати в окремий стандарт, подібно до того, як раніше були виділені вимоги до мобільних застосунків і IoT.
* WebRTC – у зв’язку зі зростаючою популярністю цієї технології, її специфічні виклики та міркування безпеки тепер охоплено окремим підрозділом.

Також було докладено зусиль, щоб розділи та секції були структуровані навколо логічно пов’язаних груп вимог.

Ця реструктуризація призвела до створення додаткових розділів:

* Самодостатні токени – раніше об’єднані в розділі управління сесіями, Самодостатні токени тепер визнані окремим механізмом і фундаментальним елементом безстанового обміну даними (наприклад, у OAuth та OIDC). Через їхні унікальні аспекти безпеки вони розглядаються в окремому розділі, у версії 5.x запроваджено нові вимоги.
* Безпека веб-фронтенду – з огляду на зростаючу складність браузерних застосунків та поширення архітектур, що базуються виключно на API, вимоги до безпеки фронтенду винесено в окремий розділ.
* Безпечне програмування та архітектура – нові вимоги, що охоплюють загальні практики безпеки, які не вписувалися у існуючі розділи, зібрані тут.

Інші організаційні зміни у версії 5.0 були спрямовані на покращення прозорості намірів. Наприклад, вимоги щодо валідації вхідних даних було перенесено до розділу, присвяченого бізнес-логіці, що відображає їхню роль у забезпеченні дотримання бізнес-правил, замість того, щоб групувати їх з санітизацією та кодуванням.

Раніше існуючий розділ V1 Архітектура було вилучено. Його початкові секції містили вимоги, що виходили за межі сфери стандарту, а наступні частини були розподілені по відповідних розділах, причому дублікати вимог було усунуто та за потреби уточнено.

## Removal of Direct Mappings to Other Standards

Direct mappings to other standards have been removed from the main body of the standard. The aim is to prepare a mapping with the OWASP Common Requirement Enumeration (CRE) project, which in turn will link ASVS to a range of OWASP projects and external standards.

Direct mappings to CWE and NIST are no longer maintained, as explained below.

### Reduced Coupling with NIST Digital Identity Guidelines

The NIST [Digital Identity Guidelines (SP 800-63)](https://pages.nist.gov/800-63-3/) have long served as a reference for authentication and authorization controls. In version 4.x, certain chapters were closely aligned with NIST's structure and terminology.

While these guidelines remain an important reference, strict alignment introduced challenges, including less widely recognized terminology, duplication of similar requirements, and incomplete mappings. Version 5.0 moves away from this approach to improve clarity and relevance.

### Moving Away from Common Weakness Enumeration (CWE)

The [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) provides a useful taxonomy of software security weaknesses. However, challenges such as category-only CWEs, difficulties in mapping requirements to a single CWE, and the presence of imprecise mappings in version 4.x have led to the decision to discontinue direct CWE mappings in version 5.0.

## Rethinking Level Definitions

Version 4.x described the levels as L1 ("Minimum"), L2 ("Standard"), and L3 ("Advanced"), with the implication that all applications handling sensitive data should meet at least L2.

Version 5.0 addresses several issues with this approach which are described in the following paragraphs.

As a practical matter, whereas version 4.x used tick marks for level indicators, 5.x uses a simple number on all formats of the standard including markdown, PDF, DOCX, CSV, JSON and XML. For backwards compatibility, legacy versions of the CSV, JSON and XML outputs which still use tick marks are also generated.

### Easier Entry Level

Feedback indicated that the large number of Level 1 requirements (~120), combined with its designation as the "minimum" level that is not good enough for most applications, discouraged adoption. Version 5.0 aims to lower this barrier by defining Level 1 primarily around first-layer defense requirements, resulting in clearer and fewer requirements at that level. To demonstrate this numerically, in v4.0.3 there were 128 L1 requirements out of a total of 278 requirements, representing 46%. In 5.0.0 there are 70 L1 requirements out of a total of 345 requirements, representing 20%.

### The Fallacy of Testability

A key factor in selecting controls for Level 1 in version 4.x was their suitability for assessment through "black box" external penetration testing. However, this approach was not fully aligned with the intent of Level 1 as the minimum set of security controls. Some users argued that Level 1 was insufficient for securing applications, while others found it too difficult to test.

Relying on testability as a criterion is both relative and, at times, misleading. The fact that a requirement is testable does not guarantee that it can be tested in an automated or straightforward manner. Moreover, the most easily testable requirements are not always those with the greatest security impact or the simplest to implement.

As such, in version 5.0, the level decisions were made primarily based on risk reduction and also keeping in mind the effort to implement.

### Not Just About Risk

The use of prescriptive, risk-based levels that mandate a specific level for certain applications has proven to be overly rigid. In practice, the prioritization and implementation of security controls depend on multiple factors, including both risk reduction and the effort required for implementation.

Therefore, organizations are encouraged to achieve the level that they feel like they should be achieving based on their maturity and the message they want to send to their users.
