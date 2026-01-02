import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 transition-all duration-200" +
  " hover-elevate active-elevate-2",
  {
    variants: {
      variant: {
        default:
          "bg-primary text-primary-foreground border border-primary-border shadow-[0_0_12px_hsl(var(--accent-primary)/0.2)] hover:shadow-[0_0_20px_hsl(var(--accent-primary)/0.35)]",
        destructive:
          "bg-destructive text-destructive-foreground border border-destructive-border shadow-[0_0_12px_hsl(var(--status-danger)/0.2)] hover:shadow-[0_0_20px_hsl(var(--status-danger)/0.35)]",
        outline:
          "border [border-color:var(--button-outline)] shadow-xs active:shadow-none hover:border-[hsl(var(--neon-cyan)/0.5)] hover:shadow-[0_0_15px_hsl(var(--accent-primary)/0.15)]",
        secondary: "border bg-secondary text-secondary-foreground border border-secondary-border hover:border-[hsl(var(--neon-cyan)/0.4)] hover:shadow-[0_0_12px_hsl(var(--accent-primary)/0.1)]",
        ghost: "border border-transparent hover:bg-[hsl(var(--neon-cyan)/0.08)] hover:text-[hsl(var(--neon-cyan))]",
        neon: "bg-[hsl(var(--neon-cyan)/0.08)] border border-[hsl(var(--neon-cyan)/0.4)] text-[hsl(var(--neon-cyan))] shadow-[0_0_15px_hsl(var(--accent-primary)/0.2)] hover:shadow-[0_0_25px_hsl(var(--accent-primary)/0.4)] hover:border-[hsl(var(--neon-cyan)/0.7)]",
      },
      // Heights are set as "min" heights, because sometimes Ai will place large amount of content
      // inside buttons. With a min-height they will look appropriate with small amounts of content,
      // but will expand to fit large amounts of content.
      size: {
        default: "min-h-9 px-4 py-2",
        sm: "min-h-8 rounded-md px-3 text-xs",
        lg: "min-h-10 rounded-md px-8",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button"
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    )
  },
)
Button.displayName = "Button"

export { Button, buttonVariants }
