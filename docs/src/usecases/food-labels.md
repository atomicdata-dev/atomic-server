# Atomic Data for food label standardization

In most countries, food producers are required to provide nutritional information on the packages of products, which helps citizens to make informed decisions about what to eat.
But how about we upgrade these labels to machine-readable, atomic data?
We could describe products using Atomic Data, and put their identifiers (Subject URLs) as QR codes on packages.
Imagine these scenarios:

## Scan labels to get detailed, reliable, interactive information

You want to know more about some new cereal you've just bought.
You scan the QR code on the package.
A web app opens that shows detailed, yet highly visual information about its nutritional value.
The screen is no longer limited to what realistically fits on a package.
The elements are interactive, and provide explanations.
Everything is translated to the user's language.
If the food is (soon to be) expired, the app will clearly and visually alert you.
Click on the question mark next to `granulated sugars`, and you get an explanation of what this means to your health.
E-numbers are clickable, too, and help you instantly understand far more about what they represent.
When AR glasses become technologically feasible, you could even help people make better decisions while doing grocery shopping.

Using _links_ instead of _names_ helps to guide consumers to _trustworthy_ pages that communicate clearly.
The alternative is that they use search engines, and maybe end up reading misinformation.

## Provide nutritional advice based on shopping behavior

You order a bunch of products on your favorite groceries delivery app.
When going to the payment screen, you are shown a nutritional overview of your order.
You see that with this diet, you might have a deficit of the Lysene amino acid.
The shopping cart suggest adding egg, dairy or soy to your diet.
This can be done, because the groceries app can easily check detailed information about the food in your shopping cart, and reason about your dietary intake.

## How to achieve all this

1. The governing body (e.g. the European Commision) should set up an [Atomic Server](https://github.com/atomicdata-dev/atomic-server/) and host it on some recognizable domain.
1. Create the [Class](https://atomicdata.dev/classes/Class) for a food product, containing the same (or more) information that is shown on food packages.
1. Create the Class for Ingredient.
1. Create instances for various Ingredients. Start with the E-numbers, work your way up to all kinds of used ingredients. Add Translations.
1. Give instructions to Producers on how to describe their Products. Give them to option to host their own Server and control their own data, and give them the option to use some EU server.
