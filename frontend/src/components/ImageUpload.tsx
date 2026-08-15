import { useCallback, useState } from "react";
import { useDropzone } from "react-dropzone";
import { Upload, FileImage, AlertCircle } from "lucide-react";

interface Props {
  onUpload: (file: File) => void;
  isLoading: boolean;
}

const MAX_SIZE = 100 * 1024 * 1024;
const ACCEPTED = {
  "image/jpeg": [".jpg", ".jpeg"],
  "image/png": [".png"],
  "image/webp": [".webp"],
  "image/tiff": [".tiff", ".tif"],
  "image/bmp": [".bmp"],
};

export default function ImageUpload({ onUpload, isLoading }: Props) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<string | null>(null);

  const onDrop = useCallback(
    (accepted: File[], rejected: { errors: { message: string }[] }[]) => {
      setError(null);
      if (rejected.length > 0) {
        const msg = rejected[0]?.errors[0]?.message ?? "Invalid file";
        setError(msg);
        return;
      }
      const file = accepted[0];
      if (!file) return;
      setSelectedFile(file);
      const url = URL.createObjectURL(file);
      setPreview(url);
    },
    [],
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: ACCEPTED,
    maxSize: MAX_SIZE,
    multiple: false,
    disabled: isLoading,
  });

  const handleAnalyze = () => {
    if (selectedFile) onUpload(selectedFile);
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div
        {...getRootProps()}
        className={`relative border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all duration-200 ${
          isDragActive
            ? "border-blue-500 bg-blue-500/10"
            : "border-slate-600 hover:border-slate-500 bg-slate-900/50"
        } ${isLoading ? "opacity-50 pointer-events-none" : ""}`}
      >
        <input {...getInputProps()} />

        {preview ? (
          <div className="space-y-4">
            <img
              src={preview}
              alt="Preview"
              className="max-h-48 mx-auto rounded-lg shadow-lg"
            />
            <div className="text-sm text-slate-400">
              <p className="font-medium text-slate-200">
                {selectedFile?.name}
              </p>
              <p>{selectedFile ? formatSize(selectedFile.size) : ""}</p>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="mx-auto w-16 h-16 rounded-full bg-slate-800 flex items-center justify-center">
              {isDragActive ? (
                <FileImage className="w-8 h-8 text-blue-400" />
              ) : (
                <Upload className="w-8 h-8 text-slate-400" />
              )}
            </div>
            <div>
              <p className="text-lg font-medium text-slate-200">
                {isDragActive ? "Drop image here" : "Upload image for analysis"}
              </p>
              <p className="text-sm text-slate-500 mt-1">
                JPEG, PNG, WebP, TIFF, BMP up to 100MB
              </p>
            </div>
          </div>
        )}
      </div>

      {error && (
        <div className="mt-3 flex items-center gap-2 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {selectedFile && !isLoading && (
        <button
          onClick={handleAnalyze}
          className="mt-4 w-full py-3 px-6 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors duration-200"
        >
          Analyze Image
        </button>
      )}
    </div>
  );
}
