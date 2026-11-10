"use client";
import React, { useState, useEffect } from "react";
import Editor from "@monaco-editor/react";
import { Code, Terminal } from "lucide-react";

interface CodeEditorProps {
  value: string;
  onChange?: (value: string | undefined) => void;
  language?: string;
  readOnly?: boolean;
  height?: string;
}

export default function CodeEditor({
  value,
  onChange,
  language = "python",
  readOnly = false,
  height = "420px",
}: CodeEditorProps) {
  const [monacoLoaded, setMonacoLoaded] = useState(false);
  const [forceFallback, setForceFallback] = useState(false);

  // If Monaco doesn't signal ready within 2.5 seconds, enable resilient fallback
  useEffect(() => {
    const timer = setTimeout(() => {
      if (!monacoLoaded) {
        setForceFallback(true);
      }
    }, 2500);
    return () => clearTimeout(timer);
  }, [monacoLoaded]);

  const lineCount = (value || "").split("\n").length;
  const lineNumbers = Array.from({ length: Math.max(lineCount, 12) }, (_, i) => i + 1);

  if (forceFallback) {
    return (
      <div className="relative rounded-lg overflow-hidden border border-gray-800 bg-gray-950 font-mono text-sm">
        <div className="flex items-center justify-between px-4 py-2 bg-gray-900/90 border-b border-gray-800 text-xs text-gray-400">
          <div className="flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Python Source Editor</span>
          </div>
          <button
            type="button"
            onClick={() => setForceFallback(false)}
            className="text-xs text-cyan-400 hover:text-cyan-300 underline"
          >
            Try Monaco Editor
          </button>
        </div>
        <div className="flex" style={{ minHeight: height, maxHeight: height }}>
          {/* Line Numbers */}
          <div className="select-none py-3 px-3 bg-gray-900/60 border-r border-gray-800/80 text-gray-600 text-right font-mono text-xs leading-6">
            {lineNumbers.map((num) => (
              <div key={num}>{num}</div>
            ))}
          </div>
          {/* Textarea */}
          <textarea
            value={value}
            onChange={(e) => onChange && onChange(e.target.value)}
            readOnly={readOnly}
            placeholder="# Paste your Python code here..."
            spellCheck={false}
            className="w-full h-full p-3 bg-transparent text-gray-200 font-mono text-sm leading-6 resize-none outline-none focus:ring-1 focus:ring-cyan-500/50"
            style={{ minHeight: height, maxHeight: height }}
            onKeyDown={(e) => {
              if (e.key === "Tab") {
                e.preventDefault();
                const start = e.currentTarget.selectionStart;
                const end = e.currentTarget.selectionEnd;
                const updated = value.substring(0, start) + "    " + value.substring(end);
                onChange && onChange(updated);
                setTimeout(() => {
                  e.currentTarget.selectionStart = e.currentTarget.selectionEnd = start + 4;
                }, 0);
              }
            }}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="relative rounded-lg overflow-hidden border border-gray-800 bg-gray-950">
      <div className="flex items-center justify-between px-3 py-1.5 bg-gray-900/60 border-b border-gray-800 text-xs text-gray-500">
        <span className="font-mono text-gray-400">Python · AST Engine</span>
        <button
          type="button"
          onClick={() => setForceFallback(true)}
          className="text-gray-400 hover:text-gray-300 text-xs flex items-center gap-1"
        >
          <Code className="w-3 h-3" />
          <span>Lightweight Mode</span>
        </button>
      </div>
      <Editor
        height={height}
        language={language}
        value={value}
        onChange={onChange}
        theme="vs-dark"
        onMount={() => setMonacoLoaded(true)}
        options={{
          readOnly,
          fontSize: 14,
          fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, monospace",
          lineNumbers: "on",
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          automaticLayout: true,
          bracketPairColorization: { enabled: true },
          renderLineHighlight: readOnly ? "none" : "line",
          wordWrap: "on",
          padding: { top: 12, bottom: 12 },
          tabSize: 4,
          insertSpaces: true,
          folding: true,
          scrollbar: {
            verticalScrollbarSize: 6,
            horizontalScrollbarSize: 6,
          },
        }}
      />
    </div>
  );
}
