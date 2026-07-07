# Forms / Survey Research

The forms feature in atomic will allow the user to create forms and surveys and share them with a link or embed them on a website.
The creation of the form will happen in the data-browser similar to how other resource types are created (new > form).
The published form will be served from a different route than the data-browser since we don't want to include the whole data-browser bundle in the published form.

## Forms vs. Surveys

There is a slight difference between forms and surveys

|  | **Forms** | **Survey** |
| --- | --- | --- |
| **User’s Goals** | To *get* something done (e.g., register, buy, log in). | To *share* a perspective or provide feedback. |
| **Creator's Goal** | Collect factual, structured, individual data. | Analyze aggregate trends, opinions, and feelings. |
| **Data Types** | Objective & Static (Name, Email, SKU number). | Subjective & Nuanced (Likert scales, sentiment). |
| **User Motivation** | High. They want the outcome at the end of the form. | Low to Moderate. They are usually doing you a favor. |

**The UX Impact of this Distinction**
Because a user filling out a **form** wants the end result (like a plane ticket or a new account), they will tolerate a bit more friction, though they expect extreme efficiency.
Conversely, a user taking a **survey** has very little skin in the game. If the UX is frustrating, confusing, or feels too long, they will drop out instantly. Therefore, survey UX must prioritize minimizing cognitive fatigue and maximizing engagement.

## What kind of forms can we expect?

Since most forms in the wild rely on backend logic, they are often build directly and professionally into the business’s website or app. The person that would actually use our tool for a form submission use-case is likely independent or lacks the expertise within their organization to build a form into their software. That means that we will likely not see the use-case for very complex forms that require links and checks with other systems.

Some examples of forms I expect to see:

- Invite application for a self hosted event. (Large birthday parties or community hosted tournaments etc.)
- Contact forms for small businesses. (These might require some kind of back and forth with the user and the organization but that could also be handled by the organization via email.
- Support/Ticket forms

## What kind of surveys can we expect?

While there are many tools these days that modernize surveys (typeform etc.). I’ve never actually seen them used in scientific research surveys for some reason. Most of the time these use tools that look dated and aren’t as engaging as modern tools. I’m not sure what would be needed for these kinds of people to start using our potential survey tools. My first thought would be data handling and maybe privacy guarantees.

I do expect surveys like:

- Rating a product
- Feedback forms after an event
- Research surveys from students doing smaller projects that do not require giant sample sizes.

****

## Tool Comparisons

|Name            |Notes                                                                                                                                           |View             |Screen Types                              |Cool Features                                                                                                                                                                                                                                                     |Keyboard Controls                                  |Input Types                                                                                                                                                                                             |Multi-Input Questions|Theming                                                                                          |Branching|Opensource|Results View                              |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------|-----------------|------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------|-------------------------------------------------------------------------------------------------|---------|----------|------------------------------------------|
|Typeform        |Only supports one question per slide. Only the address field has multiple inputs.                                                               |slide-show       |Question                                  |                                                                                                                                                                                                                                                                  |Next Question: Enter  Scroll to navigate questions.|AI Follow-up questions, Email, Freeform Video/Audio input, Likert, Number, Option Ranking, Phone, Pick-Many, Pick-Many (Combo box), Pick-One, Pick-One (Image), Plain Date, Rating, Signature, Text, URL|No                   |Adding images, Fonts, Text Color, BG Color, Accent Color                                         |Yes      |No        |Summary, Survey Performance Insight, Table|
|Forms.md        |Heavily inspired by Typeform. But forms are made in code.                                                                                       |slide-show       |                                          |                                                                                                                                                                                                                                                                  |Not tested                                         |                                                                                                                                                                                                        |No                   |                                                                                                 |Yes      |Yes       |                                          |
|Fillout         |Looks very nice, far greater page customization than Typeform.  Way better than Typeform imo.                                                   |Pages            |Ending, Payment, Question, Review, Welcome|  • Pre-fill values based on other questions.   • Use values inside any text.   • Table input   • URL-parameters                                                                                                                                                  |Basic browser navigation                           |Address, Currency, DateTime, Email, Freeform Video/Audio input, Likert, Option Ranking, Phone, Pick-Many (Combo box), Pick-One (Image), Plain Date, Rating, Signature, URL                              |Yes                  |Color, Images, Rich Text, Custom HTML and CSS with Pro plan.                                     |Yes      |No        |Summary, Survey Performance Insight, Table|
|Tally           |A form structured like a document. Great concept but kind of limiting in practice. There is no way to edit field parameters as far as I can see.|Document         |                                          |  • Document like editor.   • Iframe embeds.                                                                                                                                                                                                                      |                                                   |                                                                                                                                                                                                        |No                   |Font, BG/Text colors, Accent colors  Pro: Widths, input sizes and color customization. Custom CSS|Yes      |No        |                                          |
|Jotform         |Looks a bit wacky. Design doesn’t look very consistent.  Has lots of special widgets that other competitors don’t have.                         |Pages, slide-show|Question                                  |  • Encryption   • Lots of unique widgets                                                                                                                                                                                                                         |                                                   |                                                                                                                                                                                                        |Yes                  |Very customizable with custom css                                                                |Yes      |No        |                                          |
|SurveyMonkey    |More traditional, page based. At first glance the UX is a bit outdated (Slow server rendered actions). Seems focused on research surveys.       |Pages            |Question                                  |  • Research features like question randomization   • AI question type detection (auto selects type based on name)   • Lots of pre made questions (Might be useful for researchers?)   • Quiz mode (Select what answers are correct and give points based on that)|                                                   |                                                                                                                                                                                                        |Yes                  |Pre-made themes with more customization in pro plan.  Default looks a bit bland.                 |Yes      |No        |                                          |
|Airtable Forms  |Basic forms that submit data to airtable.  Does not have a lot of advanced features.                                                            |Single Page      |                                          |                                                                                                                                                                                                                                                                  |                                                   |                                                                                                                                                                                                        |No                   |                                                                                                 |Yes      |No        |                                          |
|Cryptpad (Forms)| Only a few basic question types. Not a serious competitor.                                                                                |                 |                                          |E2E encryption                                                                                                                                                                                                                                                    |                                                   |Pick-One, Text                                                                                                                                                                                          |No                   |                                                                                                 |Yes      |No        |                                          |

## Our requirements

### Must have

- **Form Builder**: Add pages and questions, configure question types and settings.
- **Submission without agents**: We need to be able to create data without the user needing to create an agent.
- **/form/:id route**: The server should serve the published form from a different route than the data-browser. The published form should not rely on the data-browser bundle.
- **Basic field types**: We need field types
  - Short Text
  - Long Text
  - Email
  - Number
  - Date / DateTime
  - Checkbox
  - Multiple Choice Radio Groups
  - Multi-Select (Checkboxes)
- **Non input types**: Things like paragraphs and titles
- **Basic Field Options**: e.g. Required, Min-Max value/length, Default value, placeholder text, label, helper text
- **Collect output in a table**: Submissions should be placed in a table resource (use existing table feature).
- **Publish/Unpublish forms**: Forms should be able to be set to publish or unpublished, when published submissions can be made.

### Should have

- **Form Embedding:** Make the forms embeddable on other websites.
- **Preview mode**: Most form/survey apps have a preview mode to see how the form will look. If possible we should try to reuse as much of the actual embedded form rendering code as possible.
- **Progress Bar**: Option to display a progress bar in the form.
- **Captcha’s**: Some way prevent bot/spam submissions.
- **Private links**: The user should be able to gate the form with codes included in the search params. A code can then only be used once.
- **More specialized field types:**
  - Phone number
  - Currency
  - URL
  - File upload
  - Signature
  - Multi-Select (dropdown)
  - Table input (Lets the user input multiple rows with preset columns)
  - Likert scale
  - Choice Matrix
  - Location/Map (Location based on raw coordinates)
  - Address (Location based on address information)
  - Picture Choice
- **More non-input types**: Like Images, info banners, embeds etc.
- **Branching**: Hide/show questions or pages based on other answers.
- **Styling**: Customize the form them to match the creators brand (Important when embedding on their website).
- **Results Summary View**: We should show a view with the results graphed per question.

### Could have

- **AI Suggested question types:** Since we already have a few AI generation features in Atomic we can reuse the infra to generate questions based on their name (and possibly other questions in the form). We could let an AI model generate a json object containing type and potential values/settings. For example: for the title “What is your age?” the AI could generate something like `{"type": "multi-select", "options": ["0 - 5", "6 - 10", "11 - 15"...]}`
- **AI Form builder**: We can create a skill for the AI agent to edit/build forms.
- **Question Randomization:** Often used by researchers to filter out priming bias.
- **Dynamic text**: Use values of previous questions as values or in titles of followup questions.
- **Partial submissions**: Save non submitted forms as drafts that can be finished by the user later. This would either require us to somehow link the draft to a user or save the draft in local storage (or in opfs but that’s probably a bit overkill for an iframe).
- **Scheduled publish/unpublish**: Surveys often have a set runtime after which the form should no longer be available. We could allow the user to automate this.

### Won’t have

- **Document-like editor**: While it is a cool idea, I’m not convinced this is the correct paradigm for a form editor. The Editor view and final form view are too different from one another to make sense. From a data standpoint it would be kind of a nightmare. The editor would most likely be build using tiptap so we’d need to map the nodes to properties on the form resource and keep them in sync with the state of the document.
- **Payments**: Out of scope?

## Technical Considerations

### Schema

We should keep the submission class and form class distinct from each other. The submission is a flat custom class generated by the form builder that contains all the data of a single submission. Each question in the form maps to a property on the data class. The form/question resources can then have additional properties used for rendering and logic without affecting the data class. A form will have a list of pages, the pages will hold the questions. We could use a type of block based layout where we have a field property on the page that contains a list of both form fields and layout components like text, images, headings etc.

Here is a quick/incomplete list of classes we could make:
*\* = required*
**Form**

- *name - String
- *data-class - Resource<Class>
- *pages - ResourceArray<FormPage>
- form-styling - Resource<FormStyling>

**FormPage**

- name - String
- *fields - ResourceArray (no class-type since atomic does not support multiple class-types at the moment)
- condition - ResourceArray<FormCondition>
- cover-image - Resource<File>
- image-position - Resource<Tag> - [top, left, right, cover?]

**FormCondition**

- field - Resource<FormField>
- inverted - Boolean
- operator - Resource<Tag> - [equals, contains, les-than, greater-than, regex?]
- value - JSON (the value type depends on the field so we can use JSON since these can be any valid JSON type)

**— Field types —**

**FormField** - Generic field class, used in combination with a second class that specifies the type of field.

- *name - String
- description - String - rendered as helper text
- maps-to - Resource<Property>
- condition - ResourceArray<FormCondition>
- required - Boolean
- validation - ResourceArray<FormCondition>

**FormTextField**

- placeholder - String
- min - Float
- max - Float

**FormLikertField**

- min - Float
- max - Float
- min-label - String
- max-label - String

…

**— Layout types —**

**FormHeading**

- *name - String
- condition - ResourceArray<FormCondition>

**FormParagraph**

- description - Markdown

**FormBanner**

- name - String
- description - Markdown

**FormRow**

- *fields - ResourceArray
- condition - ResourceArray<FormCondition>

…
