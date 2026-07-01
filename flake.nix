{
  description = "S3 Boot Script Analyzer development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in
    {
      devShells.${system}.default = pkgs.mkShellNoCC {
        packages = with pkgs; [
          python312
          uv

          kaitai-struct-compiler
          shellcheck

          nodejs_24
          markdownlint-cli2
        ];

        UV_PYTHON_DOWNLOADS = "never";
        UV_PROJECT_ENVIRONMENT = ".venv";
        PYLINTHOME = ".pylint.d";

        shellHook = ''
          echo "Loaded S3 Boot Script Analyzer dev shell"
          echo "Python: $(python --version)"
          echo "uv: $(uv --version)"
          echo "Kaitai: $(kaitai-struct-compiler --version 2>/dev/null || true)"
        '';
      };
    };
}
