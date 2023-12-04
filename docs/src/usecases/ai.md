# Atomic Data & Artificial Intelligence

Recent developments in machine learning (and specifically deep neural networks) have shown how powerful and versatile AI can be.
Both Atomic Data and AI can be used to store and query knowledge, but we think of these technologies as complementary due to their unique characteristics:

- Artificial Intelligence can make sense of (unstructured) data, so you can feed it any type of data. However, AIs often produce unpredictable and sometimes incorrect results.
- Atomic Data helps to make data interoperable, reliable and predictable. However, it requires very strict inputs.

There are two ways in which Atomic Data and AI can help each other:

- AI can help to make creating Atomic Data easier.
- Atomic Data can help train AIs.
- Atomic Data can provide AIs with reliable, machine readable data for answering questions.

## Make it easier to create Atomic Data using AI

While writing text, an AI might help make suggestions to disambiguate whatever it is you're writing about.
For example, you may mention `John` and your knowledge graph editor (like `atomic-server`) could suggest `John Wayne` or `John Cena`.
When making your selection, a link will be created which helps to make your knowledge graph more easily browsable.
AI could help make these suggestions through context-aware _entity recognition_.

## Train AIs with Atomic Data

During training, you could feed Atomic Data to your AI to help it construct a reliable, consistent model of the knowledge relevant to your organization or domain.
You could use `atomic-server` as the knowledge store, and iterate over your resources and let your AI parse them.

## Provide AI with query access to answer questions

Instead of training your AI, you might provide your AI with an interface to perform queries.
Note that at this moment, I'm not aware of any AIs that can actually construct and execute queries, but because of recent advancements (e.g. ChatGPT), we know that there now exist AIs that can create SQL queries based on human text.
In the future, you might let your AI query your `atomic-server` to find reliable and up-to-date answers to your questions.
