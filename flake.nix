{
  description = "S3 Boot Script Analyzer development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      pyproject-nix,
      uv2nix,
      pyproject-build-systems,
      ...
    }:
    let
      inherit (nixpkgs) lib;

      forAllSystems = lib.genAttrs lib.systems.flakeExposed;

      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };

      overlay = workspace.mkPyprojectOverlay {
        sourcePreference = "wheel";
      };

      editableOverlay = workspace.mkEditablePyprojectOverlay {
        root = "$REPO_ROOT";
      };

      pythonSets = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python312;

          packageOverlay = final: prev: {
            s3bootscript-analyzer = prev.s3bootscript-analyzer.overrideAttrs (old: {
              nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [
                pkgs.kaitai-struct-compiler
              ];

              preBuild = ''
                ${pkgs.bash}/bin/bash scripts/generate-kaitai
              '';
            });
          };
        in
        (pkgs.callPackage pyproject-nix.build.packages {
          inherit python;
        }).overrideScope (
          lib.composeManyExtensions [
            pyproject-build-systems.overlays.wheel
            overlay
            packageOverlay
          ]
        )
      );
    in
    {
      packages = forAllSystems (system: {
        default = pythonSets.${system}.mkVirtualEnv "s3bootscript-analyzer-env" workspace.deps.default;
      });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/s3bootscript-analyzer";
        };
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          pythonSet = pythonSets.${system}.overrideScope editableOverlay;

          virtualenv = pythonSet.mkVirtualEnv "s3bootscript-analyzer-dev-env" workspace.deps.all;
        in
        {
          default = pkgs.mkShellNoCC {
            packages = [
              virtualenv
              pkgs.uv

              pkgs.kaitai-struct-compiler
              pkgs.shellcheck
              pkgs.jq
              pkgs.markdownlint-cli2
            ];

            env = {
              UV_NO_SYNC = "1";
              UV_PYTHON = pythonSet.python.interpreter;
              UV_PYTHON_DOWNLOADS = "never";
              PYLINTHOME = ".pylint.d";
            };

            shellHook = ''
              unset PYTHONPATH
              export REPO_ROOT=$(git rev-parse --show-toplevel)

              echo "Loaded S3 Boot Script Analyzer dev shell"
              echo "Python: $(python --version)"
              echo "uv: $(uv --version)"
              echo "Kaitai: $(kaitai-struct-compiler --version 2>/dev/null || true)"
            '';
          };
        }
      );
    };
}
