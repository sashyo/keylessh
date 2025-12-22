import { useQuery } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { api, type LicenseInfo, type PricingInfo, type BillingHistoryItem, type SubscriptionTier } from "@/lib/api";
import { CreditCard, Users, Server, Check, ExternalLink, FileText, AlertCircle } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";

function formatDate(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function formatCurrency(amount: number, currency: string): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
  }).format(amount / 100);
}

function UsageBar({ current, limit, label }: { current: number; limit: number; label: string }) {
  const percentage = limit === Infinity ? 0 : Math.min((current / limit) * 100, 100);
  const isAtLimit = limit !== Infinity && current >= limit;
  const isNearLimit = limit !== Infinity && current >= limit * 0.8;

  return (
    <div className="space-y-2">
      <div className="flex justify-between text-sm">
        <span className="text-muted-foreground">{label}</span>
        <span className={isAtLimit ? "text-destructive font-medium" : ""}>
          {current} / {limit === Infinity ? "Unlimited" : limit}
        </span>
      </div>
      {limit !== Infinity && (
        <Progress
          value={percentage}
          className={isAtLimit ? "[&>div]:bg-destructive" : isNearLimit ? "[&>div]:bg-amber-500" : ""}
        />
      )}
    </div>
  );
}

function TierCard({
  tier,
  name,
  maxUsers,
  maxServers,
  priceId,
  isCurrentTier,
  onUpgrade,
  stripeConfigured,
  enterpriseContactUrl,
}: {
  tier: SubscriptionTier;
  name: string;
  maxUsers: number;
  maxServers: number;
  priceId: string | null;
  isCurrentTier: boolean;
  onUpgrade: (priceId: string) => void;
  stripeConfigured: boolean;
  enterpriseContactUrl?: string;
}) {
  const features = [
    `${maxUsers === -1 ? "Unlimited" : maxUsers} users`,
    `${maxServers === -1 ? "Unlimited" : maxServers} servers`,
    "SSH key signing",
    "Audit logs",
    tier !== "free" && "Priority support",
    tier === "enterprise" && "Custom integrations",
  ].filter(Boolean) as string[];

  return (
    <Card className={isCurrentTier ? "border-primary" : ""}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg">{name}</CardTitle>
          {isCurrentTier && <Badge>Current Plan</Badge>}
        </div>
        <CardDescription>
          {tier === "free" && "Get started with basic features"}
          {tier === "pro" && "For growing teams"}
          {tier === "enterprise" && "For large organizations"}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <ul className="space-y-2">
          {features.map((feature) => (
            <li key={feature} className="flex items-center gap-2 text-sm">
              <Check className="h-4 w-4 text-primary" />
              {feature}
            </li>
          ))}
        </ul>
        {!isCurrentTier && priceId && stripeConfigured && (
          <Button className="w-full" onClick={() => onUpgrade(priceId)}>
            Upgrade to {name}
          </Button>
        )}
        {!isCurrentTier && tier === "enterprise" && !priceId && (
          <Button
            variant="outline"
            className="w-full"
            onClick={() => {
              if (enterpriseContactUrl) {
                window.open(enterpriseContactUrl, "_blank", "noopener,noreferrer");
              }
            }}
            disabled={!enterpriseContactUrl}
            title={!enterpriseContactUrl ? "Set VITE_ENTERPRISE_CONTACT_URL to enable this button" : undefined}
          >
            Contact us
          </Button>
        )}
        {isCurrentTier && tier !== "free" && (
          <Button variant="outline" className="w-full" disabled>
            Current Plan
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

export default function AdminLicense() {
  const { toast } = useToast();
  const [location] = useLocation();
  const enterpriseContactUrl = import.meta.env.VITE_ENTERPRISE_CONTACT_URL as string | undefined;

  // Check for success/canceled query params
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("success") === "true") {
      toast({
        title: "Subscription updated",
        description: "Your subscription has been successfully updated.",
      });
      // Clean up URL
      window.history.replaceState({}, "", "/admin/license");
    } else if (params.get("canceled") === "true") {
      toast({
        title: "Checkout canceled",
        description: "You can try again when you're ready.",
        variant: "destructive",
      });
      window.history.replaceState({}, "", "/admin/license");
    }
  }, [toast]);

  const { data: licenseInfo, isLoading: licenseLoading } = useQuery({
    queryKey: ["/api/admin/license"],
    queryFn: () => api.admin.license.get(),
  });

  const { data: pricingInfo, isLoading: pricingLoading } = useQuery({
    queryKey: ["/api/admin/license/prices"],
    queryFn: () => api.admin.license.getPrices(),
  });

  const { data: billingHistory, isLoading: billingLoading } = useQuery({
    queryKey: ["/api/admin/license/billing"],
    queryFn: () => api.admin.license.getBillingHistory(),
  });

  const handleUpgrade = async (priceId: string) => {
    try {
      const { url } = await api.admin.license.createCheckout(priceId);
      if (url) {
        window.location.href = url;
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to create checkout session. Please try again.",
        variant: "destructive",
      });
    }
  };

  const handleManageSubscription = async () => {
    try {
      const { url } = await api.admin.license.createPortal();
      if (url) {
        window.location.href = url;
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to open billing portal. Please try again.",
        variant: "destructive",
      });
    }
  };

  const isLoading = licenseLoading || pricingLoading;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">License Management</h1>
          <p className="text-muted-foreground">
            Manage your subscription and view usage
          </p>
        </div>
        {licenseInfo?.subscription?.stripeCustomerId && (
          <Button variant="outline" onClick={handleManageSubscription}>
            <CreditCard className="h-4 w-4 mr-2" />
            Manage Subscription
          </Button>
        )}
      </div>

      {!pricingInfo?.stripeConfigured && (
        <Alert>
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            Stripe is not configured. Contact your administrator to enable subscription management.
          </AlertDescription>
        </Alert>
      )}

      {/* Current Plan & Usage */}
      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CreditCard className="h-5 w-5" />
              Current Plan
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {isLoading ? (
              <Skeleton className="h-20 w-full" />
            ) : (
              <>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-2xl font-bold">{licenseInfo?.tierName || "Free"}</p>
                    <p className="text-sm text-muted-foreground">
                      {licenseInfo?.subscription?.status === "active"
                        ? "Active subscription"
                        : licenseInfo?.subscription?.status === "past_due"
                        ? "Payment past due"
                        : licenseInfo?.subscription?.status === "canceled"
                        ? "Subscription canceled"
                        : "Free tier"}
                    </p>
                  </div>
                  <Badge
                    variant={
                      licenseInfo?.subscription?.status === "active"
                        ? "default"
                        : licenseInfo?.subscription?.status === "past_due"
                        ? "destructive"
                        : "secondary"
                    }
                  >
                    {licenseInfo?.subscription?.status || "Free"}
                  </Badge>
                </div>
                {licenseInfo?.subscription?.currentPeriodEnd && (
                  <p className="text-sm text-muted-foreground">
                    {licenseInfo.subscription.cancelAtPeriodEnd
                      ? "Expires on "
                      : "Renews on "}
                    {formatDate(licenseInfo.subscription.currentPeriodEnd)}
                  </p>
                )}
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="h-5 w-5" />
              Usage
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {isLoading ? (
              <Skeleton className="h-20 w-full" />
            ) : (
              <>
                <UsageBar
                  current={licenseInfo?.usage.users || 0}
                  limit={licenseInfo?.limits.maxUsers || 5}
                  label="Users"
                />
                <UsageBar
                  current={licenseInfo?.usage.servers || 0}
                  limit={licenseInfo?.limits.maxServers || 2}
                  label="Servers"
                />
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Available Plans */}
      <Card>
        <CardHeader>
          <CardTitle>Available Plans</CardTitle>
          <CardDescription>Choose the plan that best fits your needs</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="grid gap-4 md:grid-cols-3">
              <Skeleton className="h-64 w-full" />
              <Skeleton className="h-64 w-full" />
              <Skeleton className="h-64 w-full" />
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-3">
              {pricingInfo &&
                (["free", "pro", "enterprise"] as const).map((tier) => (
                  <TierCard
                    key={tier}
                    tier={tier}
                    name={pricingInfo.tiers[tier].name}
                    maxUsers={pricingInfo.tiers[tier].maxUsers}
                    maxServers={pricingInfo.tiers[tier].maxServers}
                    priceId={pricingInfo.tiers[tier].priceId}
                    isCurrentTier={licenseInfo?.tier === tier}
                    onUpgrade={handleUpgrade}
                    stripeConfigured={pricingInfo.stripeConfigured}
                    enterpriseContactUrl={tier === "enterprise" ? enterpriseContactUrl : undefined}
                  />
                ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Billing History */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Billing History
          </CardTitle>
          <CardDescription>Your recent invoices and payments</CardDescription>
        </CardHeader>
        <CardContent>
          {billingLoading ? (
            <Skeleton className="h-32 w-full" />
          ) : billingHistory && billingHistory.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Date</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Amount</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {billingHistory.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell>{formatDate(item.createdAt)}</TableCell>
                    <TableCell>{item.description || "Subscription payment"}</TableCell>
                    <TableCell>{formatCurrency(item.amount, item.currency)}</TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          item.status === "paid"
                            ? "default"
                            : item.status === "failed"
                            ? "destructive"
                            : "secondary"
                        }
                      >
                        {item.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {item.invoicePdf && (
                        <Button
                          variant="ghost"
                          size="sm"
                          asChild
                        >
                          <a href={item.invoicePdf} target="_blank" rel="noopener noreferrer">
                            <ExternalLink className="h-4 w-4" />
                          </a>
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground text-center py-8">
              No billing history yet
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
