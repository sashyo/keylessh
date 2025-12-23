import {
  File,
  FileCode,
  FileImage,
  FileText,
  FileVideo,
  FileAudio,
  FileArchive,
  Folder,
  FolderOpen,
  Link2,
  FileQuestion,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface FileIconProps {
  name: string;
  type: "file" | "directory" | "symlink" | "other";
  isOpen?: boolean;
  className?: string;
}

const extensionIconMap: Record<string, typeof File> = {
  // Code files
  js: FileCode,
  jsx: FileCode,
  ts: FileCode,
  tsx: FileCode,
  py: FileCode,
  rb: FileCode,
  go: FileCode,
  rs: FileCode,
  java: FileCode,
  c: FileCode,
  cpp: FileCode,
  h: FileCode,
  hpp: FileCode,
  cs: FileCode,
  php: FileCode,
  swift: FileCode,
  kt: FileCode,
  scala: FileCode,
  sh: FileCode,
  bash: FileCode,
  zsh: FileCode,
  fish: FileCode,
  ps1: FileCode,
  json: FileCode,
  yaml: FileCode,
  yml: FileCode,
  toml: FileCode,
  xml: FileCode,
  html: FileCode,
  css: FileCode,
  scss: FileCode,
  less: FileCode,
  sql: FileCode,
  graphql: FileCode,
  vue: FileCode,
  svelte: FileCode,

  // Text files
  txt: FileText,
  md: FileText,
  markdown: FileText,
  rst: FileText,
  log: FileText,
  csv: FileText,
  conf: FileText,
  cfg: FileText,
  ini: FileText,
  env: FileText,

  // Images
  png: FileImage,
  jpg: FileImage,
  jpeg: FileImage,
  gif: FileImage,
  svg: FileImage,
  webp: FileImage,
  ico: FileImage,
  bmp: FileImage,
  tiff: FileImage,
  psd: FileImage,

  // Video
  mp4: FileVideo,
  mkv: FileVideo,
  avi: FileVideo,
  mov: FileVideo,
  wmv: FileVideo,
  webm: FileVideo,
  flv: FileVideo,

  // Audio
  mp3: FileAudio,
  wav: FileAudio,
  ogg: FileAudio,
  flac: FileAudio,
  aac: FileAudio,
  m4a: FileAudio,
  wma: FileAudio,

  // Archives
  zip: FileArchive,
  tar: FileArchive,
  gz: FileArchive,
  bz2: FileArchive,
  xz: FileArchive,
  "7z": FileArchive,
  rar: FileArchive,
  tgz: FileArchive,
  tbz2: FileArchive,
  deb: FileArchive,
  rpm: FileArchive,
};

function getFileIcon(name: string): typeof File {
  const ext = name.split(".").pop()?.toLowerCase();
  if (ext && extensionIconMap[ext]) {
    return extensionIconMap[ext];
  }
  return File;
}

export function FileIcon({ name, type, isOpen, className }: FileIconProps) {
  const iconClass = cn("h-4 w-4 shrink-0", className);

  switch (type) {
    case "directory":
      return isOpen ? (
        <FolderOpen className={cn(iconClass, "text-yellow-500")} />
      ) : (
        <Folder className={cn(iconClass, "text-yellow-500")} />
      );
    case "symlink":
      return <Link2 className={cn(iconClass, "text-blue-400")} />;
    case "other":
      return <FileQuestion className={cn(iconClass, "text-muted-foreground")} />;
    default: {
      const Icon = getFileIcon(name);
      return <Icon className={iconClass} />;
    }
  }
}
