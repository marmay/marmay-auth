# NixOS module for the marmay-auth authentication service.
#
# The service is a pure identity provider: it holds the Ed25519
# signing key and the OAuth2 client secret, and issues short-lived
# identity assertions to applications on the trust domain. Consumers
# (competences instances, CMS, ...) only need the PUBLIC key.
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.marmay-auth;

  maintenancePage = pkgs.writeTextDir "maintenance.html" ''
    <!DOCTYPE html>
    <html lang="de">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta http-equiv="refresh" content="10">
      <title>Der Authentifizierungsdienst ist gerade nicht erreichbar.</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, -apple-system, sans-serif;
               min-height: 100vh; display: flex; flex-direction: column;
               background: #fafaf9; color: #1c1917; }
        .bar { background: #d97706; height: 6px; flex-shrink: 0; }
        .content { flex: 1; display: flex; justify-content: center;
                   align-items: center; padding: 2rem; }
        .card { background: white; border-radius: 12px; padding: 2.5rem;
                max-width: 28rem; text-align: center;
                box-shadow: 0 1px 3px rgba(0,0,0,.1); }
        h1 { font-size: 1.25rem; margin-bottom: .75rem; }
        p { color: #57534e; line-height: 1.6; margin-bottom: .5rem; }
        .en { color: #a8a29e; font-size: .9rem; margin-top: 1rem; }
        .hint { font-size: .8rem; color: #a8a29e; margin-top: 1.25rem; }
      </style>
    </head>
    <body>
      <div class="bar"></div>
      <div class="content">
        <div class="card">
          <h1>Der Authentifizierungsdienst ist gerade nicht erreichbar.</h1>
          <p>In Folge von Wartungsarbeiten kann es zu Ausfällen kommen,
             die wenige Minuten dauern.</p>
          <p class="en">Temporarily unavailable &mdash; the application
             is being updated and will be back shortly.</p>
          <p class="hint">Diese Seite wird automatisch neu geladen.
             / This page will refresh automatically.</p>
        </div>
      </div>
      <div class="bar"></div>
    </body>
    </html>
  '';
in {
  options.services.marmay-auth = {
    enable = mkEnableOption "marmay-auth authentication service";

    package = mkOption {
      type = types.package;
      # No default here: the flake's nixosModules.marmay-auth wrapper
      # injects self.packages.<system>.marmay-auth via mkDefault.
      description = "The marmay-auth package to use";
    };

    port = mkOption {
      type = types.port;
      description = "Port the authentication service listens on";
    };

    subdomain = mkOption {
      type = types.str;
      default = "auth";
      description = "Subdomain of the authentication service.";
    };

    secretsFile = mkOption {
      type = types.path;
      description = ''
        Path to the JSON configuration file with secrets: the Ed25519
        signing key (authIssuerJwk), the OAuth2 client, and
        allowedReturnDomain (plus optional tokenExpiryDuration and
        laxReturnUrlCheck). Typically an agenix-managed secret; the
        service refuses files readable by group/other, so use
        owner = "marmay-auth"; mode = "0400";.
      '';
    };

    nginx = {
      enable = mkEnableOption "Nginx reverse proxy configuration";

      domain = mkOption {
        type = types.str;
        description = "Apex domain; the service is served at <subdomain>.<domain>.";
      };

      enableACME = mkOption {
        type = types.bool;
        default = true;
        description = "Enable ACME/Let's Encrypt for HTTPS";
      };

      forceSSL = mkOption {
        type = types.bool;
        default = true;
        description = "Force SSL/HTTPS redirects";
      };
    };
  };

  config = mkIf cfg.enable {
    users.users.marmay-auth = {
      isSystemUser = true;
      group = "marmay-auth";
      description = "marmay-auth authentication service user";
    };
    users.groups.marmay-auth = { };

    systemd.services.marmay-auth = {
      description = "marmay-auth authentication service";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        Type = "simple";
        User = "marmay-auth";
        Group = "marmay-auth";
        Restart = "always";
        RestartSec = "10s";

        ExecStart = concatStringsSep " " [
          "${cfg.package}/bin/marmay-auth"
          "--port ${toString cfg.port}"
          "--config ${cfg.secretsFile}"
        ];

        # Security hardening; the service holds a signing key and
        # writes nothing, so keep everything private.
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        UMask = "0077";
      };
    };

    services.nginx = mkIf cfg.nginx.enable {
      enable = true;

      recommendedProxySettings = true;
      recommendedTlsSettings = true;
      recommendedOptimisation = true;
      recommendedGzipSettings = true;

      virtualHosts."${cfg.subdomain}.${cfg.nginx.domain}" = {
        enableACME = cfg.nginx.enableACME;
        forceSSL = cfg.nginx.forceSSL;

        locations."/" = {
          proxyPass = "http://127.0.0.1:${toString cfg.port}";
          extraConfig = ''
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_intercept_errors on;
            error_page 502 503 504 /maintenance.html;
          '';
        };

        locations."= /maintenance.html" = {
          root = "${maintenancePage}";
          extraConfig = "internal;";
        };
      };
    };
  };
}
