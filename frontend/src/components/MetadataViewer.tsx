import { useState } from "react";
import { ChevronDown, ChevronRight, Database } from "lucide-react";

interface Props {
  metadata: Record<string, unknown>;
}

export default function MetadataViewer({ metadata }: Props) {
  const [expanded, setExpanded] = useState(false);

  const categories = Object.entries(metadata);

  if (categories.length === 0) {
    return (
      <div className="text-sm text-slate-500 italic">
        No metadata findings available
      </div>
    );
  }

  return (
    <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 flex items-center gap-3 hover:bg-slate-700/30 transition-colors"
      >
        <Database className="w-5 h-5 text-blue-400" />
        <span className="text-sm font-medium text-slate-200 flex-1 text-left">
          Metadata Explorer
        </span>
        <span className="text-xs text-slate-500">
          {categories.length} categories
        </span>
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-slate-500" />
        ) : (
          <ChevronRight className="w-4 h-4 text-slate-500" />
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-slate-700/50 pt-3 space-y-3">
          {categories.map(([category, data]) => (
            <MetadataCategory key={category} name={category} data={data} />
          ))}
        </div>
      )}
    </div>
  );
}

function MetadataCategory({
  name,
  data,
}: {
  name: string;
  data: unknown;
}) {
  const [open, setOpen] = useState(false);

  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 text-xs text-slate-400 uppercase tracking-wider hover:text-slate-300"
      >
        {open ? (
          <ChevronDown className="w-3 h-3" />
        ) : (
          <ChevronRight className="w-3 h-3" />
        )}
        {name}
      </button>
      {open && (
        <div className="mt-1 ml-5 space-y-0.5">
          {renderValue(data)}
        </div>
      )}
    </div>
  );
}

function renderValue(data: unknown): React.ReactNode {
  if (data === null || data === undefined) {
    return <span className="text-xs text-slate-500 italic">null</span>;
  }

  if (typeof data === "string" || typeof data === "number" || typeof data === "boolean") {
    return (
      <span className="text-xs font-mono text-slate-300">{String(data)}</span>
    );
  }

  if (Array.isArray(data)) {
    return (
      <div className="space-y-1">
        {data.map((item, i) => (
          <div key={i} className="pl-2 border-l border-slate-700/50">
            {renderValue(item)}
          </div>
        ))}
      </div>
    );
  }

  if (typeof data === "object") {
    const entries = Object.entries(data as Record<string, unknown>);
    return (
      <div className="space-y-0.5">
        {entries.map(([key, val]) => (
          <div key={key} className="flex gap-2 text-xs">
            <span className="text-slate-500 font-mono whitespace-nowrap">
              {key}:
            </span>
            <span className="text-slate-300 font-mono break-all">
              {typeof val === "object"
                ? JSON.stringify(val, null, 0)
                : String(val ?? "")}
            </span>
          </div>
        ))}
      </div>
    );
  }

  return <span className="text-xs text-slate-500">{String(data)}</span>;
}
