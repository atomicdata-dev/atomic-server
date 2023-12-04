{{#title Atomic Data for Surveys}}
# Atomic Data for Surveys

Surveys and Questionnaires haven't been evolving that much over the past few years.
However, Atomic Data has a couple of unique characteristics that would make it especially suitable for surveys.
It could help make surveys easier to **fill in**, easier to **analyze**, easier to **create**, and more **privacy friendly**.

- **Re-useable survey responses** which enable **pre-filled form fields** which can save the respondent a lot of time. They also make it possible for users to use their own responses to **gather insights**, for example into their own health.
- **Question standardization** which helps researchers to re-use (validated) questions, which saves time for the researcher
- **Privacy friendly, yet highly personalized invites** as a researcher, send profile descriptions to servers, and let the servers tell if the question is relevant.

## Re-useable survey responses

Since many surveys describe personal information, it makes sense, as a respondent, to have a way of storing the information you filled in in a place that you control.
Making this possible enables a few nice use cases.

1.  **Auto-fill forms**. Previously entered response data could be usable while filling in new surveys. This could result in a UX similar to auto-filling forms, but far more powerful and rich than browsers currently support.
2.  **Analyze your own personal data**. Standardized survey responses could also be used to gather insights into your own personal information. For example, filling in a survey about how your shortness of breath linked to air pollution has been today could be used in a different app to make a graph that visualizes how your shortness of breath has progressed over the months for personal insight.

Achieving something like this requires a high degree of standardization in both the surveys and the responses. The survey and its questions should provide information about:

- The **question**. This is required in all survey questions, of course.
- The **required datatype** of the response, such as 'string', or 'datetime' or some 'enumeration'.
- A (link to a) **semantic definition** of the property being described. This is a bit more obscure: all pieces of linked data use links, instead of keys, to describe the relation between some resource and its property. For example, a normal resource might have a 'birthdate', while in linked data, we'd use '<https://schema.org/birthDate>'. This semantic definition makes things easier to share, because it prevents misinterpretation. Links remove ambiguity.
- **A query description**. This is even more obscure, but perhaps the most interesting. A query description means describing how a piece of information can be retrieved. Perhaps a question in a survey will want to know what your payment pointer is. If a piece of software wants to auto-fill this field, it needs to know where it can find your payment pointer.

## Question Standardization

We can think of Questions as Resources that have a URL, and can be shared.
Sharing questions like that can make it easier to use the same questions across surveys, which in turn can make it easier to interpret data.
Some fields (e.g. medical) have highly standardized questions, which have been validated by studies.
These Question resources should contain information about:

- The **question** itself and its translations
- The **datatype** of the response (e.g. `date`, `string`, `enum`), denoted by the [Property](https://atomicdata.dev/classes/Property) of the response.
- The **path of the data**, relative to the user. For example, a user's `birthdate` can be found by going to `/ profile birthdate`

[Atomic Schema](../schema/intro.md) and [Atomic Paths](../core/paths.md) can be of value here.

## Privacy friendly invites with client-side filtering

Currently, a researcher needs to either build their own panel, or use a service that has a lot of respondents.
Sometimes, researchers will need a very specific target audience, like a specific age group, nationality, gender, or owners of specific types of devices.
Targeting these individuals is generally done by having a large database of personal information from many individuals.
But there is another way of doing this: **client-side filtering**
Instead of asking for the users data, and storing it centralized, we could send queries to decentralized personal data stores.
There queries basically contain the targeting information and an invitation.
The query is executed on the personal data store, and if the user characteristics align with the desired participants profile, the user receives an invite.
The user only sees invitations that are highly relevant, without sharing _any_ information with the researcher.

The Atomic Data specification solves at least part of this problem.
[Paths](../core/paths.md) are used to describe the queries that researchers make.
[AtomicServer](https://github.com/atomicdata-dev/atomic--rust/blob/master/server/README.md) can be used as the personal online data store.

However, we still need to specify the process of sending a request to an individual (probably by introducing an [inbox](https://github.com/ontola/atomic-data/issues/28))
