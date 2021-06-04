.\doc-build.ps1
reportgenerator "-reports:..\..\test\unit\coverage.json" "-targetdir:..\..\docs\articles\coverage" -reporttypes:HTML
docfx ../../docfx/docfx.json -t "templates\discordfx" --serve