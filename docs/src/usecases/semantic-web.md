# Atomic Data for the Semantic Web

The term 'Semantic Web' was popularized in [a paper of the same name](https://www-sop.inria.fr/acacia/cours/essi2006/Scientific%20American_%20Feature%20Article_%20The%20Semantic%20Web_%20May%202001.pdf) published in 2001 by three people, including the inventor of the World Wide Web: Tim Berners-Lee.
In this paper, a vision was shared for how a higher degree of standardization on the internet could lead to a bunch of interesting innovations.
For example, it describes how an appointment for a doctor is scheduled automatically by a "semantic agent", by checking the location of the person, comparing that to doctors in the area, getting reviews and checking the availability in the calendar.
By making the web machine-readable, we could get far more interoperability and therefore new applications that make our lives easier.
All of this would have been made possible by using linked data.

It has been 20 years since this paper, and it is indeed easier then ever to make an appointment with a professional.
If can yell "hairdresser" at my phone, and I instantly see the nearest one with a high rating with a 'book now' button that checks our calendars.
So... we made it?
Unfortunately, this problem and many similar ones have not been solved by the semantic web: they have been solved by big companies that know everything about us, and have monopolized so much of the data on the internet.
Tech giants like Google and Microsoft have created ecosystems that integrate many types of (free) services, have huge databases containing all kinds of related stuff, and as a result, provide us with nice user experiences.
A high degree of _centralization_, instead of _standardization_, turned out to be a sufficient solution, too.
But of course, this centralized approach comes at a serious cost.
The first problem is we get _vendor lock-in_, which means that it becomes harder to switch from service to service.
We can't take our data from Whatsapp and take it to Telegram, for example, or our Twitter feed to Mastadon.
The second problem is that our usage goals do not align with the tech giants.
We might want to see a list of recent activity from our friends when we open facebook, but facebook's investors might want us to simply look at as much ads as possible.

But of course, the internet isn't just tech giants - there are a lot of enthousiasts that really want to see the decentralized, semantic web succeed.

The Semantic Web wasn't just an idea and a paper - there were a lot of standards involved, all of which were properly defined and managed by the W3C, the organization that standardizes so much of our web.
But the adoption of most of these standards is pretty low, unfortunately.

## Why the semantic web didn't take off

Before we'll discuss why Semantic Web related standards (most importantly its core data model: RDF) aren't being used too much, you need to know that I have company called Ontola which has been specialized in semantic web technologies.
We love this vision of a semantic web, and have a strong dedication to make this a reality.
We've built many libraries, full stack apps and services on RDF, and I really do think we've built technically unique products.
By going through this process, we discovered how technologically hard it is to actually build semantic web apps.
I'm actually pretty sure that we're one of the very few companies that have built a full SAAS platform (the e-democracy platform [Argu.co](https://argu.co/)) that communicates exclusively with its back-end by using RDF.
You can read more about this journey in [full-stack linked data](https://ontola.io/blog/full-stack-linked-data/), but here I'll summarize why this was such a challenging and costly endeavor.

### Standards without working implementations

The Semantic Web community actually built

### A lack of proper RDF tools

A lack

### No business incentive to make data highly accessible

If you're a software company that builds a product, you probably want people to keep using your product.
Investing in an awesome export feature where your customer can easily switch to a competitor is often a risky move.
This problem is of course not unique to the semantic web, but it is

### Quirks in the RDF data model

- No native support for arrays, which leads to a lot of confusion. I've written an [article comparing various approaches](https://ontola.io/blog/ordered-data-in-rdf/) on how to deal with this as an RDF developer.
- Subject-object combinations in RDF are not necessarily unique (contrary to key-value combinations in any Map or JSON object, for example), which makes querying and storing RDF hard.
- Named Graphs add another layer of complexity for identifying where data comes from, and makes querying and storing RDF again even harder.

### Too much academic focus on reasoning, not enough on data models

> Instead of the “let’s just build something that works” attitude that made the Web (and the Internet) such a roaring success, they brought the formalizing mindset of mathematicians and the institutional structures of academics and defense contractors. They formed committees to form working groups to write drafts of ontologies that carefully listed (in 100-page Word documents) all possible things in the universe and the various properties they could have, and they spent hours in Talmudic debates over whether a washing machine was a kitchen appliance or a household cleaning device

- https://en.wikisource.org/wiki/Page:Aaron_Swartz_s_A_Programmable_Web_An_Unfinished_Work.pdf/15

### No schema language

Being able to _check and validate_ the types of data is very useful when you want people to reach consensus on how to model things.
RDF Schema was not really a schema language.

### Confusing terminology and documentation

While learning the Semantic Web, a whole bunch of new concepts need to be learned.
  Terms like

### Too much new languages and serialization formats

The Semantic Web and RDF are both older than JSON, and focused mostly on XML.
The First RDF serialization format (RDF/XML) was hard to read, hard to parse, very confusing and basically tried to combine the worst of graph-based and document-based data models.
After that, many new serialization formats appeared (N3, Turtle, JSON-LD) that made it even more confusing for developers to adopt this technology.
[Read this](https://ontola.io/blog/rdf-serialization-formats/) if you want to know more about RDF serialization formats.

### Other reading

- http://inamidst.com/whits/2008/ditching
- https://en.wikisource.org/wiki/Page:Aaron_Swartz_s_A_Programmable_Web_An_Unfinished_Work.pdf/15
- https://twobithistory.org/2018/05/27/semantic-web.html

## Why Atomic Data might give the Semantic Web a second chance

When creating Atomic Data, I tried to learn from what went wrong with the Semantic Web.

- Focus on developer experience from the start.
- **Minimize new serialization formats / languages**. Use things that people love. That's why Atomic Data uses JSON as its core serialization format, and keeps export support for all RDF formats.
- **Build applications, libraries and tools while writing the spec**. As a process, this means that every time the spec might result in a bad developer experience, I can update the specification.
- Have a schema language built in, include it in reference libraries. This results in all data being fully type safe.
- Have Subject-predicate / key-value uniqueness.
