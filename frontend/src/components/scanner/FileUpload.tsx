"use client";
import { useRef, useState } from "react";
import { Upload, AlertCircle, X } from "lucide-react";

interface FileUploadProps {
  onFileUpload: (content: string, filename: string) => void;
}

export default function FileUpload({ onFileUpload }: FileUploadProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [fileError, setFileError] = useState<string | null>(null);

  const handleFile = (file: File) => {
    setFileError(null);

    if (!file.name.endsWith(".py")) {
      setFileError("Only Python (.py) files are supported.");
      return;
    }

    if (file.size > 512 * 1024) {
      setFileError("File too large. Maximum size is 512 KB.");
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (!content?.trim()) {
        setFileError("The selected file appears to be empty.");
        return;
      }
      onFileUpload(content, file.name);
    };
    reader.onerror = () => setFileError("Failed to read file. Please try again.");
    reader.readAsText(file);
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
    e.target.value = "";
  };

  const handleDrop = (e: React.DragEvent<HTMLButtonElement>) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  };

  return (
    <div className="flex flex-col gap-1.5">
      <input
        ref={inputRef}
        type="file"
        accept=".py"
        onChange={handleChange}
        className="hidden"
        aria-label="Upload Python file"
      />
      <button
        onClick={() => { setFileError(null); inputRef.current?.click(); }}
        onDrop={handleDrop}
        onDragOver={(e) => e.preventDefault()}
        className="flex items-center gap-2 px-4 py-2.5 border border-gray-700 hover:border-cyan-500/50 hover:text-cyan-400 text-gray-300 font-semibold rounded-lg transition-all text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
        title="Upload a Python (.py) file to scan"
      >
        <Upload className="w-4 h-4 shrink-0" />
        Upload .py File
      </button>

      {fileError && (
        <div className="flex items-center gap-2 px-3 py-2 bg-red-950/40 border border-red-500/30 rounded-lg text-red-400 text-xs max-w-xs">
          <AlertCircle className="w-3.5 h-3.5 shrink-0" />
          <span className="flex-1">{fileError}</span>
          <button onClick={() => setFileError(null)} className="shrink-0 hover:text-red-300 transition-colors">
            <X className="w-3 h-3" />
          </button>
        </div>
      )}
    </div>
  );
}
