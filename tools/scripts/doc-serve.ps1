Copy-Item ..\..\test\unit\coverage.json ..\..\docfx_project\articles\TESTING.md
Copy-Item ..\..\CHANGELOG.md ..\..\docfx_project\articles\CHANGELOG.md
Copy-Item ..\..\README.md ..\..\docfx_project\articles\README.md
..\docfx\docfx.exe build ../../docfx_project/docfx.json
..\docfx\docfx.exe ../../docfx_project/docfx.json -t "templates\discordfx" --serve