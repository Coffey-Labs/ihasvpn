import type { ReactNode } from "react";
import { Link, useLocation } from "wouter";
import { Activity, ClipboardList, LayoutDashboard, Settings, Smartphone, Users } from "lucide-react";
import { isStaff } from "../api";
import { useAuth, useLive } from "../state";
import { Mark } from "./Mark";
import { ThemeToggle } from "./ThemeSwitch";
import { UserMenu } from "./UserMenu";
import { Legal } from "./Legal";

// Account is reached through the user menu, so it is not a nav item.
const staffGroups = [
  {
    label: "Overview",
    items: [
      { href: "/", label: "Dashboard", icon: LayoutDashboard },
      { href: "/peers", label: "Peers", icon: Activity },
      { href: "/devices", label: "My devices", icon: Smartphone },
    ],
  },
  {
    label: "Administration",
    items: [
      { href: "/settings", label: "Settings", icon: Settings },
      { href: "/users", label: "Users", icon: Users },
      { href: "/audit", label: "Audit log", icon: ClipboardList },
    ],
  },
];
// A user has one page: their devices, which is also their home.
const userGroups = [{ label: "Overview", items: [{ href: "/", label: "My devices", icon: Smartphone }] }];

function isActive(href: string, location: string) {
  return href === "/" ? location === "/" : location.startsWith(href);
}

function LivePill() {
  const { connected } = useLive();
  return (
    <span className={`live-pill${connected ? " on" : ""}`} title={connected ? "Live updates connected" : "Live updates reconnecting"}>
      <i /> {connected ? "Live" : "Reconnecting"}
    </span>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  const { me } = useAuth();
  const staff = isStaff(me?.role);
  const groups = staff ? staffGroups : userGroups;
  const tabs = groups.flatMap((g) => g.items);
  return (
    <div className="shell">
      {/* Phones and narrow windows: brand and account controls up top. */}
      <header className="topbar">
        <Link href="/" className="brand" aria-label="ihasvpn home">
          <Mark size={30} />
          <span className="brand-name">ihasvpn</span>
        </Link>
        <div className="topbar-right">
          {staff && <LivePill />}
          <ThemeToggle />
          <UserMenu placement="down" />
        </div>
      </header>

      {/* Desktop: everything lives in the sidebar. */}
      <aside className="sidebar">
        <Link href="/" className="brand" aria-label="ihasvpn home">
          <Mark size={34} />
          <span>
            <span className="brand-name">ihasvpn</span>
            <span className="brand-sub">Self-hosted WireGuard</span>
          </span>
        </Link>
        <nav className="nav" aria-label="Main">
          {groups.map((g) => (
            <div className="nav-group" key={g.label}>
              <div className="nav-label">{g.label}</div>
              {g.items.map((it) => {
                const Icon = it.icon;
                return (
                  <Link key={it.href} href={it.href} className={isActive(it.href, location) ? "active" : ""} aria-current={isActive(it.href, location) ? "page" : undefined}>
                    <Icon />
                    <span>{it.label}</span>
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="sidebar-tools">
            {staff && <LivePill />}
            <ThemeToggle />
          </div>
          <UserMenu placement="up" showName />
          <Legal />
        </div>
      </aside>

      <main className="main" id="main">
        {children}
      </main>

      {/* Phones: primary navigation as a tab bar within thumb reach. */}
      <nav className="tabbar" aria-label="Main">
        {tabs.map((it) => {
          const Icon = it.icon;
          const active = isActive(it.href, location);
          return (
            <Link key={it.href} href={it.href} className={active ? "active" : ""} aria-current={active ? "page" : undefined}>
              <Icon />
              <span>{it.label}</span>
            </Link>
          );
        })}
      </nav>
    </div>
  );
}
