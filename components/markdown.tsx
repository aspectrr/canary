import { Fragment, type ReactNode } from "react";

/**
 * Minimal, dependency-free Markdown renderer covering the subset the report
 * uses: headings, bold, inline code, code fences, links, and ordered/unordered
 * lists. Not a full Markdown engine — kept tiny on purpose.
 */

function renderInline(text: string, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  // Token regex: bold **x**, code `x`, link [t](u), or plain run.
  const re = /(\*\*([^*]+)\*\*)|(`([^`]+)`)|(\[([^\]]+)\]\(([^)\s]+)\))/g;
  let last = 0;
  let i = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    const key = `${keyPrefix}-${i++}`;
    if (m[2] !== undefined) {
      nodes.push(<strong key={key}>{m[2]}</strong>);
    } else if (m[4] !== undefined) {
      nodes.push(
        <code
          key={key}
          className="bg-stone px-1.5 py-0.5 font-mono text-[0.85em] text-ink/75"
        >
          {m[4]}
        </code>,
      );
    } else if (m[6] !== undefined && m[7] !== undefined) {
      nodes.push(
        <a
          key={key}
          href={m[7]}
          target="_blank"
          rel="noopener noreferrer"
          className="font-medium text-ink underline decoration-ink/30 underline-offset-2 hover:decoration-ink"
        >
          {m[6]}
        </a>,
      );
    }
    last = m.index + m[0].length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

export function Markdown({ source }: { source: string }) {
  const lines = source.replace(/\r/g, "").split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;
  let key = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Code fence.
    if (line.trim().startsWith("```")) {
      const buf: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        buf.push(lines[i]);
        i++;
      }
      i++; // skip closing fence
      blocks.push(
        <pre
          key={key++}
          className="overflow-x-auto bg-ink p-3 font-mono text-xs leading-relaxed text-bone"
        >
          <code>{buf.join("\n")}</code>
        </pre>,
      );
      continue;
    }

    // Heading.
    const h = line.match(/^(#{1,3})\s+(.*)$/);
    if (h) {
      const level = h[1].length;
      const content = renderInline(h[2], `h${key}`);
      const cls =
        level === 1
          ? "mt-4 mb-1 text-lg font-semibold"
          : level === 2
            ? "mt-3 mb-1 text-base font-semibold"
            : "mt-2 mb-0.5 text-sm font-semibold";
      blocks.push(
        <p key={key++} className={cls}>
          {content}
        </p>,
      );
      i++;
      continue;
    }

    // Ordered list.
    if (/^\d+\.\s+/.test(line)) {
      const items: ReactNode[] = [];
      while (i < lines.length && /^\d+\.\s+/.test(lines[i])) {
        const text = lines[i].replace(/^\d+\.\s+/, "");
        items.push(<li key={items.length}>{renderInline(text, `ol${key}-${items.length}`)}</li>);
        i++;
      }
      blocks.push(
        <ol
          key={key++}
          className="my-1 ml-5 list-decimal space-y-1 [&>li]:pl-1"
        >
          {items}
        </ol>,
      );
      continue;
    }

    // Unordered list.
    if (/^[-*]\s+/.test(line)) {
      const items: ReactNode[] = [];
      while (i < lines.length && /^[-*]\s+/.test(lines[i])) {
        const text = lines[i].replace(/^[-*]\s+/, "");
        items.push(<li key={items.length}>{renderInline(text, `ul${key}-${items.length}`)}</li>);
        i++;
      }
      blocks.push(
        <ul key={key++} className="my-1 ml-5 list-disc space-y-1 [&>li]:pl-1">
          {items}
        </ul>,
      );
      continue;
    }

    // Blank line.
    if (line.trim() === "") {
      i++;
      continue;
    }

    // Paragraph (merge consecutive non-empty, non-special lines).
    const buf: string[] = [line];
    i++;
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !/^(#{1,3}\s|[-*]\s|\d+\.\s|```)/.test(lines[i])
    ) {
      buf.push(lines[i]);
      i++;
    }
    blocks.push(
      <p key={key++} className="my-1.5 leading-relaxed">
        {renderInline(buf.join(" "), `p${key}`)}
      </p>,
    );
  }

  return <Fragment>{blocks}</Fragment>;
}
