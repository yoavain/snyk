Notes:
- when a pom includes a module cli plugin is not scanning the dependencies of the modules but maven:dependencyTree is returning it


- sprint boot example we should look at supporting Bill of Materials patter where we fix the version in the <parent> tag, because user specifies  the version of a framework.
- for framework deps we can do either add version tag in the dependencies or bump the whole framework in parent.

Notes on effective pom:
- it does not tell us where the location of the parent is, so that is still a missing piece.

- further research the versions plugin http://www.mojohaus.org/versions-maven-plugin/ it did not correctly apply upgrades to dependencies in all scenarios when tested.
- do we need to bump the project version as part of a fix? We don't do this in SCM

Possible remediations:
- use effective pom and if all versions are defined in the same pom then inline the version upgrade
- use effective pom & if we notice the dependency points to a known framework parent then bump the parent in the pom to the fixed version. Assuming Deps & framework version are versioned together.
-
