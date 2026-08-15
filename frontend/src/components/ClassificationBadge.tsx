import type { ClassificationType } from "../types/analysis";

const CLASSIFICATION_STYLES: Record<
  ClassificationType,
  { bg: string; text: string; label: string }
> = {
  verified_ai_provenance: {
    bg: "bg-red-500/20 border-red-500/50",
    text: "text-red-400",
    label: "Verified AI Provenance",
  },
  likely_ai_generated: {
    bg: "bg-orange-500/20 border-orange-500/50",
    text: "text-orange-400",
    label: "Likely AI-Generated",
  },
  likely_ai_edited: {
    bg: "bg-amber-500/20 border-amber-500/50",
    text: "text-amber-400",
    label: "Likely AI-Edited",
  },
  conventionally_edited: {
    bg: "bg-blue-500/20 border-blue-500/50",
    text: "text-blue-400",
    label: "Conventionally Edited",
  },
  likely_original: {
    bg: "bg-green-500/20 border-green-500/50",
    text: "text-green-400",
    label: "Likely Original",
  },
  mixed_provenance: {
    bg: "bg-purple-500/20 border-purple-500/50",
    text: "text-purple-400",
    label: "Mixed Provenance",
  },
  inconclusive: {
    bg: "bg-gray-500/20 border-gray-500/50",
    text: "text-gray-400",
    label: "Inconclusive",
  },
};

interface Props {
  classification: string | null;
  size?: "sm" | "lg";
}

export default function ClassificationBadge({
  classification,
  size = "sm",
}: Props) {
  const key = (classification ?? "inconclusive") as ClassificationType;
  const style = CLASSIFICATION_STYLES[key] ?? CLASSIFICATION_STYLES.inconclusive;

  const sizeClasses =
    size === "lg"
      ? "px-4 py-2 text-lg font-semibold"
      : "px-2.5 py-1 text-xs font-medium";

  return (
    <span
      className={`inline-flex items-center rounded-md border ${style.bg} ${style.text} ${sizeClasses}`}
    >
      {style.label}
    </span>
  );
}
