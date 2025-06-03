# Оцінювання та Cертифікація

## Позиція OWASP щодо Сертифікації за ASVS та Знаків Довіри

OWASP, як незалежна некомерційна організація, що не здійснює сертифікацію постачальників, фахівців з перевірки або програмного забезпечення. Жодне підтвердження відповідності, знак довіри чи сертифікат, що заявляє про відповідність ASVS, не має офіційного схвалення OWASP, тому організаціям слід з обережністю ставитися до заяв сторонніх сторін про сертифікацію за ASVS.

Організації можуть надавати послуги з оцінювання відповідності, за умови, що вони не заявляють про наявність офіційної сертифікації OWASP.

## Як перевірити відповідність ASVS

Стандарт ASVS свідомо не є приписовим щодо того, як саме здійснювати перевірку відповідності на рівні посібника з тестування. Втім, важливо акцентувати увагу на кількох ключових аспектах.

### Звітність щодо верифікації

Традиційні звіти з тестування на проникнення подають інформацію "за винятками", тобто зазначають лише виявлені порушення. Водночас, звіт про відповідність ASVS має містити скоуп, підсумок усіх перевірених вимог, перелік вимог, щодо яких були виявлені винятки, а також рекомендації щодо усунення виявлених проблем. Деякі вимоги можуть бути непридатними для певного контексту (наприклад, керування сесіями у stateless API), і це обов’язково слід зафіксувати у звіті.

### Скоуп верифікації

Організація, що розробляє застосунок, зазвичай не впроваджує всі вимоги стандарту, оскільки деякі з них можуть бути неактуальними або менш значущими залежно від функціональності застосунку. Перевіряючий повинен чітко визначити скоуп верифікації, включно з інформацією про Рівень, який організація прагне досягти, та перелік включених вимог. При цьому акцент робиться на тому, що було включено, а не на тому, що було виключено. Також слід надати обґрунтування щодо виключення вимог, які не були впроваджені.

Це дозволяє споживачу звіту з верифікації зрозуміти контекст перевірки та прийняти обґрунтоване рішення щодо рівня довіри до застосунку.

Організації, що сертифікують, можуть обирати свої методи тестування, але мають розкривати їх у звіті, причому ці методи мають бути відтворюваними. Для перевірки таких аспектів, як валідація вхідних даних, можуть використовуватися різні методи, наприклад, ручне тестування на проникнення або аналіз програмного коду, залежно від застосунку та вимог.

### Verification Mechanisms

There are a number of different techniques which may be needed to verify specific ASVS requirements. Aside from penetration testing (using valid credentials to get full application coverage), verifying ASVS requirements may require access to documentation, source code, configuration, and the people involved in the development process. Especially for verifying L2 and L3 requirements. It is standard practice to provide robust evidence of findings with detailed documentation, which may include work papers, screenshots, scripts, and testing logs. Merely running an automated tool without thorough testing is insufficient for certification, as each requirement must be verifiably tested.

The use of automation to verify ASVS requirements is a topic that is constantly of interest. It is therefore important to clarify some points related to automated and black box testing.

#### The Role of Automated Security Testing Tools

When automated security testing tools such as Dynamic and Static Application Security Testing tools (DAST and SAST) are correctly implemented in the build pipeline, they may be able to identify some security issues that should never exist. However, without careful configuration and tuning they will not provide the required coverage and the level of noise will prevent real security issues from being identified and mitigated.

Whilst this may provide coverage of some of the more basic and straightforward technical requirements such as those relating to output encoding or sanitiation, it is critical to note that these tools will be unable entirely to verify many of the more complicated ASVS requirements or those that relate to business logic and access control.

For less straightforward requirements, it is likely that automation can still be utilized but application specific verifications will need to be written to achieve this. These may be similar to unit and integration tests that the organization may already be using. It may therefore be possible to use this existing test automation infrastructure to write these ASVS specific tests. Whilst doing this will require short term investment, the long term benefits being able to continually verify these ASVS requirements will be significant.

In summary, testable using automation != running an off the shelf tool.

#### The Role of Penetration Testing

Whilst L1 in version 4.0 was optimized for "black box" (no documentation and no source) testing to occur, even then the standard was clear that it is not an effective assurance activity and should be actively discouraged.

Testing without access to necessary additional information is an inefficient and ineffective mechanism for security verification, as it misses out on the possibility of reviewing the source, identifying threats and missing controls, and performing a far more thorough test in a shorter timeframe.

It is strongly encouraged to perform documentation or source code-led (hybrid) penetration testing, which have full access to the application developers and the application's documentation, rather than traditional penetration tests. This will certainly be necessary in order to verify many of the ASVS requirements.
