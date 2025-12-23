import { ChevronRight, Home } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

interface PathBreadcrumbProps {
  path: string;
  onNavigate: (path: string) => void;
  className?: string;
}

export function PathBreadcrumb({ path, onNavigate, className }: PathBreadcrumbProps) {
  const parts = path.split("/").filter(Boolean);

  const handleClick = (index: number) => {
    if (index === -1) {
      onNavigate("/");
    } else {
      const newPath = "/" + parts.slice(0, index + 1).join("/");
      onNavigate(newPath);
    }
  };

  return (
    <div className={cn("flex items-center gap-0.5 overflow-x-auto text-sm", className)}>
      <Button
        variant="ghost"
        size="sm"
        className="h-6 px-1.5 shrink-0"
        onClick={() => handleClick(-1)}
      >
        <Home className="h-3.5 w-3.5" />
      </Button>

      {parts.map((part, index) => (
        <div key={index} className="flex items-center shrink-0">
          <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
          <Button
            variant="ghost"
            size="sm"
            className="h-6 px-1.5 font-normal"
            onClick={() => handleClick(index)}
          >
            {part}
          </Button>
        </div>
      ))}
    </div>
  );
}
