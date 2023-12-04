# Atomic Data for Education - standardized, modular e-learning

The Atomic Data specification can help make online educational content more **modular**. This has two direct benefits:

- **Separate learning goals from how they are achieved**. Some might prefer watching a video, others may want to read. Both can describe the same topic, and share the same test.
- **Improve discoverability**. Create links between topics so students know which knowledge is needed to advance to the next topic.

## Modular educational content - a model

We can think of **Knowledge** as being building blocks that we need to do certain things.
And we can think of **Lessons** as _teaching_ certain pieces of knowledge, while at the same time _requiring_ other pieces of knowledge.
For example, an algebra class might require that you already know how to multiply, add, etc.
We can think of **Test** as _verifying_ if a piece of knowledge is properly understood.

Now there's also a relationship between the **Student** and all of these things.
A student is following a bunch Lessons in which they've made some progress, has done some Tests which resulted in Scores.

Describing our educational content in this fashion has a bunch of advantages.
For students, this means they can know in advance if they can get started with a course, or if they need to learn something else first.
Conversely, they can also discover new topics that depend on their previous piece of knowledge.
For teachers, this means they can re-use existing lessons for the courses.

## What makes Atomic-Server a great tool for creating online courseware

- Powerful built-in document editor
- Drag & drop file support
- Versioning
- Open source, so no vendor lock-in, and full customizability
- Real-time updates, great for collaboration
- Online by default, so no extra hassle with putting courses on the internet

However, there is still a lot to do!

- Turn the model described above into an actual Atomic Schema data model
- Build the GUI for the application
- Add plugins / extenders for things like doing tests (without giving the answer to students!)
- Create educational content
