interface Props {
  value: number | null;
  label?: string;
  size?: "sm" | "lg";
}

export default function ConfidenceIndicator({
  value,
  label = "Confidence",
  size = "sm",
}: Props) {
  if (value === null || value === undefined) {
    return (
      <div className="text-slate-500 text-sm italic">
        {label}: N/A
      </div>
    );
  }

  const percentage = Math.round(value * 100);

  const barColor =
    percentage >= 80
      ? "bg-green-500"
      : percentage >= 50
        ? "bg-amber-500"
        : "bg-red-500";

  const textColor =
    percentage >= 80
      ? "text-green-400"
      : percentage >= 50
        ? "text-amber-400"
        : "text-red-400";

  const height = size === "lg" ? "h-3" : "h-2";

  return (
    <div className="w-full">
      <div className="flex justify-between items-center mb-1">
        <span className="text-xs text-slate-400 uppercase tracking-wider">
          {label}
        </span>
        <span className={`text-sm font-mono font-semibold ${textColor}`}>
          {percentage}%
        </span>
      </div>
      <div className={`w-full ${height} bg-slate-700 rounded-full overflow-hidden`}>
        <div
          className={`${height} ${barColor} rounded-full transition-all duration-500`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
}
