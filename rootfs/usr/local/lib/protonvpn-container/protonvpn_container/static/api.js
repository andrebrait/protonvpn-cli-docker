"use strict";
(async () => {
  const el = (tag, text, cls) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (cls) node.className = cls;
    return node;
  };
  const example = (parent, label, value) => {
    parent.append(el("h3", label, "sub-h"));
    const pre = el("pre");
    pre.append(el("code", typeof value === "string" ? value : JSON.stringify(value, null, 2)));
    parent.append(pre);
  };
  const quote = (value) => "'" + value.replaceAll("'", "'\\''") + "'";
  const status = document.getElementById("docs-status");
  try {
    const response = await fetch("/api/v1/openapi.json", { cache: "no-cache" });
    if (!response.ok) throw new Error("Cannot load contract");
    const doc = await response.json();
    const resolve = (schema) => schema.$ref ? doc.components.schemas[schema.$ref.split("/").pop()] : schema;
    const cookieFlow = document.getElementById("cookie-flow");
    example(cookieFlow, "1. Log in and save the session", `umask 077\ncurl --fail-with-body -c cookies.txt -H "Content-Type: application/json" -H "X-Requested-With: protonvpn-webui" -d '{"password":"your-webui-password"}' ${quote(location.origin + "/api/v1/login")}`);
    example(cookieFlow, "2. Read status", `curl --fail-with-body -b cookies.txt ${quote(location.origin + "/api/v1/status")}`);
    example(cookieFlow, "3. Request disconnect", `curl --fail-with-body -b cookies.txt -X POST -H "Content-Type: application/json" -H "X-Requested-With: protonvpn-webui" -d '{}' ${quote(location.origin + "/api/v1/disconnect")}`);
    example(cookieFlow, "4. Log out and clear the cookie jar", `curl --fail-with-body -b cookies.txt -c cookies.txt -X POST -H "Content-Type: application/json" -H "X-Requested-With: protonvpn-webui" -d '{}' ${quote(location.origin + "/api/v1/logout")}`);
    for (const [path, methods] of Object.entries(doc.paths)) {
      for (const [method, op] of Object.entries(methods)) {
        const fullPath = doc.servers[0].url + path;
        const card = el("section", undefined, "card");
        card.id = op.operationId;
        card.setAttribute("aria-labelledby", `h-${op.operationId}`);
        const heading = el("h2", undefined, "endpoint-title");
        heading.id = `h-${op.operationId}`;
        heading.append(el("span", method.toUpperCase(), `method ${method}`), el("code", fullPath));
        card.append(heading, el("h3", op.summary), el("p", op.description));
        const link = el("a", `${method.toUpperCase()} ${fullPath} — ${op.summary}`);
        link.href = `#${op.operationId}`;
        const li = el("li");
        li.append(link);
        document.getElementById("endpoint-links").append(li);
        for (const param of op.parameters || []) {
          card.append(el("p", `${param.name} (${param.in}${param.required ? ", required" : ", optional"}): ${param.description}`));
        }
        let curl = `curl --fail-with-body -H "Authorization: Bearer $API_KEY"`;
        const request = op.requestBody?.content["application/json"];
        if (request) {
          example(card, "JSON request", request.example);
          const schema = resolve(request.schema);
          for (const [name, prop] of Object.entries(schema.properties || {})) {
            card.append(el("p", `${name} (${prop.type}${schema.required?.includes(name) ? ", required" : ", optional"})${prop.description ? ": " + prop.description : ""}`, "note"));
          }
          curl += ` -X ${method.toUpperCase()} -H "Content-Type: application/json"`;
          // Include it even for bearer examples: login remains usable when API_KEY is disabled.
          curl += ` -H "X-Requested-With: protonvpn-webui" -d ${quote(JSON.stringify(request.example))}`;
        }
        if (path === "/login") curl += " -c cookies.txt";
        curl += ` ${quote(location.origin + fullPath)}`;
        example(card, "Run in your terminal", curl);
        if (path !== "/login" && op.security?.length !== 0) {
          const cookieCurl = curl.replace('-H "Authorization: Bearer $API_KEY"', path === "/logout" ? "-b cookies.txt -c cookies.txt" : "-b cookies.txt");
          example(card, "Cookie alternative (log in first)", cookieCurl);
        }
        if (path === "/port") example(card, "Plain-text port", `curl --fail-with-body -H "Authorization: Bearer $API_KEY" ${quote(location.origin + fullPath + "?format=text")}`);
        for (const [code, result] of Object.entries(op.responses)) {
          const details = el("details");
          details.open = code === "200";
          details.append(el("summary", `${code} · ${result.description}`));
          for (const [type, media] of Object.entries(result.content || {})) {
            if (media.example !== undefined) example(details, type, media.example);
            for (const [name, value] of Object.entries(media.examples || {})) example(details, `${type} · ${name}`, value.value);
          }
          card.append(details);
        }
        document.getElementById("endpoints").append(card);
      }
    }
    status.textContent = "OpenAPI 3.1 · JSON Schema 2020-12 · v1";
  } catch (_) {
    status.textContent = "Cannot load API documentation. Reload this page or download the OpenAPI JSON above.";
    status.className = "error";
  }
})();
