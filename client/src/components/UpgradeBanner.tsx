import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { AlertCircle } from "lucide-react";
import { useLocation } from "wouter";

interface UpgradeBannerProps {
  message: string;
  current: number;
  limit: number;
  tierName: string;
}

export function UpgradeBanner({ message, current, limit, tierName }: UpgradeBannerProps) {
  const [, setLocation] = useLocation();

  return (
    <Alert className="bg-amber-50 border-amber-200 dark:bg-amber-950/20 dark:border-amber-800">
      <AlertCircle className="h-4 w-4 text-amber-600 dark:text-amber-400" />
      <AlertDescription className="flex items-center justify-between w-full">
        <span className="text-amber-800 dark:text-amber-200">
          {message || `You've reached the ${tierName} plan limit of ${limit}. Currently using ${current}/${limit}.`}
        </span>
        <Button
          size="sm"
          variant="outline"
          className="ml-4 border-amber-600 text-amber-700 hover:bg-amber-100 dark:border-amber-400 dark:text-amber-300 dark:hover:bg-amber-950"
          onClick={() => setLocation("/admin/license")}
        >
          Upgrade Plan
        </Button>
      </AlertDescription>
    </Alert>
  );
}
