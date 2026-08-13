import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "./styles.css";

function App() {
  return (
    <main className="page-shell">
      <section className="panel" aria-labelledby="page-title">
        <p className="eyebrow">Sentinel Copilot</p>
        <h1 id="page-title">SOC investigation workspace</h1>
        <p className="description">
          Project foundation is running. The operational dashboard will be built in a later module.
        </p>
        <span className="status">Development environment ready</span>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
