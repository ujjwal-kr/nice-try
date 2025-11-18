{
  description = "Python Flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python312;
      in
      {
        devShell = pkgs.mkShell {
          buildInputs = [
            python
            python.pkgs.virtualenv
            python.pkgs.pip
            pkgs.nodejs
            pkgs.pnpm
          ];

          # Create and activate a venv named "env" when entering the dev shell.
          # Uses python -m venv (falls back to python3 or virtualenv) and sources the activate script.
          shellHook = ''
            # Create venv named "env" if it doesn't exist
            if [ ! -d env ]; then
              if command -v python >/dev/null 2>&1; then
                python -m venv env || true
              fi
              if [ ! -d env ] && command -v python3 >/dev/null 2>&1; then
                python3 -m venv env || true
              fi
              if [ ! -d env ] && command -v virtualenv >/dev/null 2>&1; then
                virtualenv env || true
              fi
            fi

            # Activate the venv if activation script exists
            if [ -f env/bin/activate ]; then
              # shellcheck source=/dev/null
              . env/bin/activate
            fi
          '';
        };
      }
    );
}