import { useState } from "react";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import {
  Building2,
  Users,
  Server,
  CheckCircle,
  ArrowRight,
  ArrowLeft,
  Loader2,
  Terminal,
  Shield,
  AlertCircle,
  ExternalLink,
  Copy,
  Check,
} from "lucide-react";

// Logo component (same as Login page)
function KeyleSSHLogo({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 36 36" className={className} xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="onboardingLogoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#ffffff"/>
          <stop offset="100%" stopColor="#a0a0a8"/>
        </linearGradient>
        <filter id="onboardingLogoGlow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="1.5" result="coloredBlur"/>
          <feMerge>
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>
      <rect width="36" height="36" rx="8" fill="hsl(120 15% 8%)"/>
      <g filter="url(#onboardingLogoGlow)">
        <path d="M10 8 L10 28" stroke="url(#onboardingLogoGrad)" strokeWidth="3" strokeLinecap="round" fill="none"/>
        <path d="M11 18 L21 8" stroke="#ffffff" strokeWidth="3" strokeLinecap="round" fill="none"/>
        <path d="M11 18 L21 28" stroke="#a0a0a8" strokeWidth="3" strokeLinecap="round" fill="none"/>
      </g>
      <rect x="25" y="21" width="5" height="7" rx="1" fill="#e0e0e0"/>
    </svg>
  );
}

type OnboardingTier = "free" | "paid";

interface OnboardingFormData {
  tier: OnboardingTier;
  organizationName: string;
  organizationSlug: string;
  adminEmail: string;
  adminFirstName: string;
  adminLastName: string;
  termsAccepted: boolean;
}

type OnboardingStep = "welcome" | "tier" | "organization" | "admin" | "provisioning" | "complete";

interface ProvisioningStatus {
  step: string;
  progress: number;
  message: string;
  error?: string;
}

export default function Onboarding() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();

  const [currentStep, setCurrentStep] = useState<OnboardingStep>("welcome");
  const [isLoading, setIsLoading] = useState(false);
  const [provisioningStatus, setProvisioningStatus] = useState<ProvisioningStatus | null>(null);
  const [inviteLink, setInviteLink] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const [formData, setFormData] = useState<OnboardingFormData>({
    tier: "free",
    organizationName: "",
    organizationSlug: "",
    adminEmail: "",
    adminFirstName: "",
    adminLastName: "",
    termsAccepted: false,
  });

  const [errors, setErrors] = useState<Partial<Record<keyof OnboardingFormData, string>>>({});

  // Validation helpers
  const isValidOrgName = (name: string): boolean => /^[a-zA-Z0-9 ]+$/.test(name);
  const isValidOrgSlug = (slug: string): boolean => /^[a-z0-9]+$/.test(slug);
  const isValidEmail = (email: string): boolean => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  // Auto-generate slug from name
  const generateSlug = (name: string): string => {
    return name.toLowerCase().replace(/[^a-z0-9]/g, "");
  };

  const handleNameChange = (value: string) => {
    setFormData(prev => ({
      ...prev,
      organizationName: value,
      organizationSlug: generateSlug(value),
    }));
    setErrors(prev => ({ ...prev, organizationName: undefined, organizationSlug: undefined }));
  };

  const handleSlugChange = (value: string) => {
    setFormData(prev => ({ ...prev, organizationSlug: value.toLowerCase() }));
    setErrors(prev => ({ ...prev, organizationSlug: undefined }));
  };

  const validateOrganizationStep = (): boolean => {
    const newErrors: Partial<Record<keyof OnboardingFormData, string>> = {};

    if (!formData.organizationName.trim()) {
      newErrors.organizationName = "Organization name is required";
    } else if (!isValidOrgName(formData.organizationName)) {
      newErrors.organizationName = "Organization name can only contain letters, numbers, and spaces";
    } else if (formData.organizationName.length < 2) {
      newErrors.organizationName = "Organization name must be at least 2 characters";
    }

    if (!formData.organizationSlug.trim()) {
      newErrors.organizationSlug = "Organization slug is required";
    } else if (!isValidOrgSlug(formData.organizationSlug)) {
      newErrors.organizationSlug = "Slug can only contain lowercase letters and numbers";
    } else if (formData.organizationSlug.length < 2) {
      newErrors.organizationSlug = "Slug must be at least 2 characters";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const validateAdminStep = (): boolean => {
    const newErrors: Partial<Record<keyof OnboardingFormData, string>> = {};

    if (!formData.adminEmail.trim()) {
      newErrors.adminEmail = "Admin email is required";
    } else if (!isValidEmail(formData.adminEmail)) {
      newErrors.adminEmail = "Please enter a valid email address";
    }

    if (!formData.adminFirstName.trim()) {
      newErrors.adminFirstName = "First name is required";
    }

    if (!formData.adminLastName.trim()) {
      newErrors.adminLastName = "Last name is required";
    }

    if (!formData.termsAccepted) {
      newErrors.termsAccepted = "You must accept the terms and conditions";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleNext = () => {
    switch (currentStep) {
      case "welcome":
        setCurrentStep("tier");
        break;
      case "tier":
        setCurrentStep("organization");
        break;
      case "organization":
        if (validateOrganizationStep()) {
          setCurrentStep("admin");
        }
        break;
      case "admin":
        if (validateAdminStep()) {
          startProvisioning();
        }
        break;
    }
  };

  const handleBack = () => {
    switch (currentStep) {
      case "tier":
        setCurrentStep("welcome");
        break;
      case "organization":
        setCurrentStep("tier");
        break;
      case "admin":
        setCurrentStep("organization");
        break;
    }
  };

  const startProvisioning = async () => {
    setCurrentStep("provisioning");
    setIsLoading(true);
    setProvisioningStatus({ step: "starting", progress: 0, message: "Starting provisioning..." });

    try {
      // Step 1: Create organization and provision TideCloak realm
      setProvisioningStatus({ step: "database", progress: 20, message: "Creating organization..." });

      // Use the unauthenticated onboarding endpoint
      const response = await fetch("/api/onboarding", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          tier: formData.tier,
          organizationName: formData.organizationName,
          organizationSlug: formData.organizationSlug,
          adminEmail: formData.adminEmail,
          adminFirstName: formData.adminFirstName,
          adminLastName: formData.adminLastName,
        }),
      });

      setProvisioningStatus({ step: "tidecloak", progress: 50, message: "Provisioning TideCloak realm..." });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `Failed with status ${response.status}`);
      }

      const result = await response.json();

      setProvisioningStatus({ step: "idp", progress: 80, message: "Configuring identity provider..." });

      if (result.inviteLink) {
        setInviteLink(result.inviteLink);
      }

      // Complete
      setProvisioningStatus({ step: "complete", progress: 100, message: "Provisioning complete!" });
      setCurrentStep("complete");

      toast({
        title: "Organization Created",
        description: `${formData.organizationName} has been successfully provisioned.`,
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Provisioning failed";
      setProvisioningStatus({
        step: "error",
        progress: 0,
        message: "Provisioning failed",
        error: errorMessage
      });
      toast({
        title: "Provisioning Failed",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyInviteLink = () => {
    if (inviteLink) {
      navigator.clipboard.writeText(inviteLink);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getStepNumber = (): number => {
    switch (currentStep) {
      case "welcome": return 1;
      case "tier": return 2;
      case "organization": return 3;
      case "admin": return 4;
      case "provisioning": return 5;
      case "complete": return 6;
      default: return 1;
    }
  };

  const totalSteps = 6;

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Header */}
      <header className="border-b border-border">
        <div className="container mx-auto px-4 sm:px-6 py-4 flex items-center gap-3">
          <KeyleSSHLogo className="h-8 w-8 sm:h-9 sm:w-9" />
          <span className="font-semibold text-base sm:text-lg text-foreground">KeyleSSH</span>
          <span className="text-muted-foreground">•</span>
          <span className="text-sm text-muted-foreground">Organization Setup</span>
        </div>
      </header>

      {/* Progress indicator */}
      {currentStep !== "welcome" && (
        <div className="container mx-auto px-4 sm:px-6 py-4">
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
            <span>Step {getStepNumber()} of {totalSteps}</span>
          </div>
          <Progress value={(getStepNumber() / totalSteps) * 100} className="h-2" />
        </div>
      )}

      {/* Main content */}
      <main className="flex-1 container mx-auto px-4 sm:px-6 py-8 flex items-center justify-center">
        <div className="w-full max-w-2xl">

          {/* Welcome Step */}
          {currentStep === "welcome" && (
            <Card>
              <CardHeader className="text-center pb-2">
                <div className="flex justify-center mb-4">
                  <div className="h-16 w-16 rounded-2xl bg-primary/10 flex items-center justify-center">
                    <Building2 className="h-8 w-8 text-primary" />
                  </div>
                </div>
                <CardTitle className="text-2xl">Welcome to KeyleSSH</CardTitle>
                <CardDescription className="text-base">
                  Let's set up your organization for secure SSH access management
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid gap-4">
                  <div className="flex items-start gap-4 p-4 rounded-lg bg-muted/50">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                      <Building2 className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <h3 className="font-medium">Create Organization</h3>
                      <p className="text-sm text-muted-foreground">
                        Set up your organization with a unique name and identifier
                      </p>
                    </div>
                  </div>

                  <div className="flex items-start gap-4 p-4 rounded-lg bg-muted/50">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                      <Users className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <h3 className="font-medium">Configure Admin</h3>
                      <p className="text-sm text-muted-foreground">
                        Set up the initial administrator account
                      </p>
                    </div>
                  </div>

                  <div className="flex items-start gap-4 p-4 rounded-lg bg-muted/50">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                      <Shield className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <h3 className="font-medium">Provision Identity</h3>
                      <p className="text-sm text-muted-foreground">
                        Automatically configure TideCloak for secure authentication
                      </p>
                    </div>
                  </div>
                </div>

                <Button onClick={handleNext} className="w-full gap-2" size="lg">
                  Get Started
                  <ArrowRight className="h-4 w-4" />
                </Button>
              </CardContent>
            </Card>
          )}

          {/* Tier Selection Step */}
          {currentStep === "tier" && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Server className="h-5 w-5" />
                  Choose Your Plan
                </CardTitle>
                <CardDescription>
                  Select the plan that best fits your organization's needs
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid gap-4">
                  {/* Free Tier */}
                  <button
                    type="button"
                    onClick={() => setFormData(prev => ({ ...prev, tier: "free" }))}
                    className={`w-full p-4 rounded-lg border-2 text-left transition-all ${
                      formData.tier === "free"
                        ? "border-primary bg-primary/5"
                        : "border-border hover:border-primary/50"
                    }`}
                  >
                    <div className="flex items-start gap-4">
                      <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${
                        formData.tier === "free" ? "bg-primary/20" : "bg-muted"
                      }`}>
                        <Users className="h-5 w-5 text-primary" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <h3 className="font-medium">Free Tier</h3>
                          <span className="text-sm text-muted-foreground">$0/month</span>
                        </div>
                        <p className="text-sm text-muted-foreground mt-1">
                          Shared infrastructure with other organizations
                        </p>
                        <ul className="mt-3 space-y-1 text-sm text-muted-foreground">
                          <li className="flex items-center gap-2">
                            <CheckCircle className="h-3.5 w-3.5 text-green-500" />
                            Up to 5 SSH servers
                          </li>
                          <li className="flex items-center gap-2">
                            <CheckCircle className="h-3.5 w-3.5 text-green-500" />
                            Up to 10 users
                          </li>
                          <li className="flex items-center gap-2">
                            <CheckCircle className="h-3.5 w-3.5 text-green-500" />
                            Organization-scoped data isolation
                          </li>
                        </ul>
                      </div>
                    </div>
                  </button>

                  {/* Paid Tier */}
                  <button
                    type="button"
                    onClick={() => setFormData(prev => ({ ...prev, tier: "paid" }))}
                    className={`w-full p-4 rounded-lg border-2 text-left transition-all ${
                      formData.tier === "paid"
                        ? "border-primary bg-primary/5"
                        : "border-border hover:border-primary/50"
                    }`}
                  >
                    <div className="flex items-start gap-4">
                      <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${
                        formData.tier === "paid" ? "bg-primary/20" : "bg-muted"
                      }`}>
                        <Shield className="h-5 w-5 text-primary" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <h3 className="font-medium">Enterprise</h3>
                          <span className="text-sm text-muted-foreground">Contact us</span>
                        </div>
                        <p className="text-sm text-muted-foreground mt-1">
                          Dedicated infrastructure with full isolation
                        </p>
                        <ul className="mt-3 space-y-1 text-sm text-muted-foreground">
                          <li className="flex items-center gap-2">
                            <CheckCircle className="h-3.5 w-3.5 text-green-500" />
                            Unlimited SSH servers
                          </li>
                          <li className="flex items-center gap-2">
                            <CheckCircle className="h-3.5 w-3.5 text-green-500" />
                            Unlimited users
                          </li>
                          <li className="flex items-center gap-2">
                            <CheckCircle className="h-3.5 w-3.5 text-green-500" />
                            Dedicated TideCloak realm
                          </li>
                          <li className="flex items-center gap-2">
                            <CheckCircle className="h-3.5 w-3.5 text-green-500" />
                            Priority support
                          </li>
                        </ul>
                      </div>
                    </div>
                  </button>
                </div>

                <div className="flex gap-3">
                  <Button variant="outline" onClick={handleBack} className="gap-2">
                    <ArrowLeft className="h-4 w-4" />
                    Back
                  </Button>
                  <Button onClick={handleNext} className="flex-1 gap-2">
                    Continue
                    <ArrowRight className="h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Organization Step */}
          {currentStep === "organization" && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Building2 className="h-5 w-5" />
                  Organization Details
                </CardTitle>
                <CardDescription>
                  Enter the basic information for your organization
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="orgName">Organization Name</Label>
                    <Input
                      id="orgName"
                      placeholder="Acme Corporation"
                      value={formData.organizationName}
                      onChange={(e) => handleNameChange(e.target.value)}
                      className={errors.organizationName ? "border-destructive" : ""}
                    />
                    {errors.organizationName && (
                      <p className="text-sm text-destructive">{errors.organizationName}</p>
                    )}
                    <p className="text-xs text-muted-foreground">
                      Only letters, numbers, and spaces are allowed
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="orgSlug">Organization Slug</Label>
                    <Input
                      id="orgSlug"
                      placeholder="acmecorp"
                      value={formData.organizationSlug}
                      onChange={(e) => handleSlugChange(e.target.value)}
                      className={errors.organizationSlug ? "border-destructive" : ""}
                    />
                    {errors.organizationSlug && (
                      <p className="text-sm text-destructive">{errors.organizationSlug}</p>
                    )}
                    <p className="text-xs text-muted-foreground">
                      Unique identifier used in URLs. Only lowercase letters and numbers.
                    </p>
                  </div>
                </div>

                <div className="flex gap-3">
                  <Button variant="outline" onClick={handleBack} className="gap-2">
                    <ArrowLeft className="h-4 w-4" />
                    Back
                  </Button>
                  <Button onClick={handleNext} className="flex-1 gap-2">
                    Continue
                    <ArrowRight className="h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Admin Step */}
          {currentStep === "admin" && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Users className="h-5 w-5" />
                  Administrator Account
                </CardTitle>
                <CardDescription>
                  Set up the initial administrator for this organization
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="firstName">First Name</Label>
                      <Input
                        id="firstName"
                        placeholder="John"
                        value={formData.adminFirstName}
                        onChange={(e) => {
                          setFormData(prev => ({ ...prev, adminFirstName: e.target.value }));
                          setErrors(prev => ({ ...prev, adminFirstName: undefined }));
                        }}
                        className={errors.adminFirstName ? "border-destructive" : ""}
                      />
                      {errors.adminFirstName && (
                        <p className="text-sm text-destructive">{errors.adminFirstName}</p>
                      )}
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="lastName">Last Name</Label>
                      <Input
                        id="lastName"
                        placeholder="Doe"
                        value={formData.adminLastName}
                        onChange={(e) => {
                          setFormData(prev => ({ ...prev, adminLastName: e.target.value }));
                          setErrors(prev => ({ ...prev, adminLastName: undefined }));
                        }}
                        className={errors.adminLastName ? "border-destructive" : ""}
                      />
                      {errors.adminLastName && (
                        <p className="text-sm text-destructive">{errors.adminLastName}</p>
                      )}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="email">Email Address</Label>
                    <Input
                      id="email"
                      type="email"
                      placeholder="admin@acmecorp.com"
                      value={formData.adminEmail}
                      onChange={(e) => {
                        setFormData(prev => ({ ...prev, adminEmail: e.target.value }));
                        setErrors(prev => ({ ...prev, adminEmail: undefined }));
                      }}
                      className={errors.adminEmail ? "border-destructive" : ""}
                    />
                    {errors.adminEmail && (
                      <p className="text-sm text-destructive">{errors.adminEmail}</p>
                    )}
                    <p className="text-xs text-muted-foreground">
                      An invite link will be sent to this email
                    </p>
                  </div>

                  <div className="flex items-start space-x-3 pt-2">
                    <Checkbox
                      id="terms"
                      checked={formData.termsAccepted}
                      onCheckedChange={(checked) => {
                        setFormData(prev => ({ ...prev, termsAccepted: checked === true }));
                        setErrors(prev => ({ ...prev, termsAccepted: undefined }));
                      }}
                    />
                    <div className="space-y-1">
                      <Label htmlFor="terms" className="text-sm font-normal cursor-pointer">
                        I agree to the{" "}
                        <a
                          href="https://tide.org/legal"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-primary hover:underline inline-flex items-center gap-1"
                        >
                          Terms & Conditions
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      </Label>
                      {errors.termsAccepted && (
                        <p className="text-sm text-destructive">{errors.termsAccepted}</p>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex gap-3">
                  <Button variant="outline" onClick={handleBack} className="gap-2">
                    <ArrowLeft className="h-4 w-4" />
                    Back
                  </Button>
                  <Button onClick={handleNext} className="flex-1 gap-2" disabled={isLoading}>
                    {isLoading ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Creating...
                      </>
                    ) : (
                      <>
                        Create Organization
                        <ArrowRight className="h-4 w-4" />
                      </>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Provisioning Step */}
          {currentStep === "provisioning" && provisioningStatus && (
            <Card>
              <CardHeader className="text-center">
                <CardTitle className="flex items-center justify-center gap-2">
                  <Loader2 className="h-5 w-5 animate-spin" />
                  Setting Up Your Organization
                </CardTitle>
                <CardDescription>
                  Please wait while we configure your environment
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <Progress value={provisioningStatus.progress} className="h-3" />

                <div className="text-center">
                  <p className="text-sm font-medium">{provisioningStatus.message}</p>
                </div>

                {provisioningStatus.error && (
                  <Alert variant="destructive">
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>{provisioningStatus.error}</AlertDescription>
                  </Alert>
                )}

                <div className="space-y-3 pt-4">
                  <div className="flex items-center gap-3 text-sm">
                    {provisioningStatus.progress >= 20 ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <div className="h-4 w-4 rounded-full border-2 border-muted" />
                    )}
                    <span className={provisioningStatus.progress >= 20 ? "" : "text-muted-foreground"}>
                      Create organization in database
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-sm">
                    {provisioningStatus.progress >= 40 ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <div className="h-4 w-4 rounded-full border-2 border-muted" />
                    )}
                    <span className={provisioningStatus.progress >= 40 ? "" : "text-muted-foreground"}>
                      Provision TideCloak realm
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-sm">
                    {provisioningStatus.progress >= 70 ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <div className="h-4 w-4 rounded-full border-2 border-muted" />
                    )}
                    <span className={provisioningStatus.progress >= 70 ? "" : "text-muted-foreground"}>
                      Configure identity provider
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-sm">
                    {provisioningStatus.progress >= 90 ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <div className="h-4 w-4 rounded-full border-2 border-muted" />
                    )}
                    <span className={provisioningStatus.progress >= 90 ? "" : "text-muted-foreground"}>
                      Generate admin invite link
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Complete Step */}
          {currentStep === "complete" && (
            <Card>
              <CardHeader className="text-center pb-2">
                <div className="flex justify-center mb-4">
                  <div className="h-16 w-16 rounded-2xl bg-green-500/10 flex items-center justify-center">
                    <CheckCircle className="h-8 w-8 text-green-500" />
                  </div>
                </div>
                <CardTitle className="text-2xl">Organization Created!</CardTitle>
                <CardDescription className="text-base">
                  {formData.organizationName} has been successfully set up
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {inviteLink && (
                  <div className="space-y-3">
                    <Label>Admin Invite Link</Label>
                    <Alert>
                      <AlertDescription className="text-sm">
                        Share this link with the administrator to complete their account setup.
                        The link expires in 12 hours.
                      </AlertDescription>
                    </Alert>
                    <div className="flex gap-2">
                      <Input
                        value={inviteLink}
                        readOnly
                        className="font-mono text-xs"
                      />
                      <Button
                        variant="outline"
                        size="icon"
                        onClick={handleCopyInviteLink}
                      >
                        {copied ? (
                          <Check className="h-4 w-4 text-green-500" />
                        ) : (
                          <Copy className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </div>
                )}

                <div className="space-y-3 pt-4 border-t">
                  <h3 className="font-medium">Next Steps</h3>
                  <ul className="space-y-2 text-sm text-muted-foreground">
                    <li className="flex items-start gap-2">
                      <span className="text-primary">1.</span>
                      Share the invite link with the organization administrator
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-primary">2.</span>
                      The admin will link their Tide account using the invite link
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-primary">3.</span>
                      The admin can then invite other users and configure servers
                    </li>
                  </ul>
                </div>

                <div className="flex gap-3 pt-4">
                  <Button
                    variant="outline"
                    onClick={() => {
                      setCurrentStep("welcome");
                      setFormData({
                        tier: "free",
                        organizationName: "",
                        organizationSlug: "",
                        adminEmail: "",
                        adminFirstName: "",
                        adminLastName: "",
                        termsAccepted: false,
                      });
                      setInviteLink(null);
                    }}
                    className="gap-2"
                  >
                    Create Another
                  </Button>
                  <Button
                    onClick={() => setLocation("/admin")}
                    className="flex-1 gap-2"
                  >
                    Go to Admin Dashboard
                    <ArrowRight className="h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-border py-4 sm:py-6">
        <div className="container mx-auto px-4 sm:px-6 text-center text-xs sm:text-sm text-muted-foreground">
          <p>Powered by KeyleSSH &middot; Tide Foundation</p>
        </div>
      </footer>
    </div>
  );
}
