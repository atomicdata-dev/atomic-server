import * as React from "../pkg/react.js";
import {useArray, useTitle, properties} from "../link/react/src/index.js";
import {ContainerNarrow} from "../components/Containers.js";
import {CardRow} from "../components/Card.js";
import ResourceInline from "./ResourceInline.js";
import {ValueForm} from "../components/forms/ValueForm.js";
function AgentPage({resource}) {
  const title = useTitle(resource);
  const [children] = useArray(resource, properties.children);
  return /* @__PURE__ */ React.createElement(ContainerNarrow, {
    about: resource.getSubject()
  }, /* @__PURE__ */ React.createElement(ValueForm, {
    resource,
    propertyURL: properties.description
  }), /* @__PURE__ */ React.createElement("h1", null, title), children.map((child) => {
    return /* @__PURE__ */ React.createElement(CardRow, {
      key: child
    }, /* @__PURE__ */ React.createElement(ResourceInline, {
      subject: child
    }));
  }));
}
export default AgentPage;
