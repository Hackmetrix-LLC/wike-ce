### Descripción

Jenkins posee una interfaz de línea de comandos (CLI) incorporada para acceder a Jenkins desde un script o entorno de shell.

Para lo mismo, utiliza la biblioteca **args4j** para analizar argumentos y opciones de comandos en el controlador de Jenkins al procesar comandos CLI. Este analizador de comandos tiene una función que reemplaza un carácter @ seguido de una ruta de archivo en un argumento con el contenido del archivo (expandAtFiles). Esta función está habilitada de forma predeterminada en las versiones Jenkins 2.441 y anteriores.

Esto permite a los atacantes leer archivos arbitrarios en el sistema de archivos del controlador de Jenkins utilizando la codificación de caracteres predeterminada del proceso del controlador de Jenkins.

Un atacante con permiso Overall/Read o con autenticación podría leer archivos completos, caso contrario, solo de forma parcial.

Jenkins has a built-in command line interface (CLI) to access Jenkins from a script or shell environment.

The previously mentioned interface uses the args4j library to parse command arguments and options on the Jenkins controller when processing CLI commands. This command parser has a feature that replaces an @ character followed by a file path in an argument with the file’s contents (expandAtFiles). This feature is enabled by default and Jenkins 2.441 and earlier.

This allows attackers to read arbitrary files on the Jenkins controller file system using the default character encoding of the Jenkins controller process.

Attackers with Overall/Read permission or authenticated can read entire files. Attackers without permission can only read sections of the files.

### Componentes Afectados

- https://url.com

### Detalles

The Hackmetrix's AppSec team discovered that the installed Jenkins CI/CD solution is vulnerable to CVE-2024-23897. This vulnerability impacts Jenkins' built-in command line interface, enabling an attacker to perform Arbitrary File Reads.

An attacker can communicate with the server using the command line and the **jenkins-cli.jar** file. This **.jar** file can be downloaded as shown in the following HTTP pair:

*HTTP Request:*

```
[REDACTED]
```

*HTTP Response:*

```
[REDACTED]
```

With the previous jar file, communication through the CLI is possible, even if the attacker is not authenticated.

PIC

After listing the available commands on the server, you can call one of the mentioned functions and pass an internal file as an argument. Resulting in the arbitrary file read of the file in the error message. For instance, the /etc/passwd file, Ubuntu distribution, and EC2 instance ID are shown:

PIC

### Impacto

As previously discussed, an unauthenticated attacker could easily access internal files, potentially leading to Remote Code Execution or Sensitive Information Disclosure.

### Remediación

Jenkins 2.442, LTS 2.426.3, and LTS 2.440.1 disables the command parser feature that replaces an **@** character followed by a file path in an argument with the file’s contents for CLI commands.

In case of problems with this fix, disable this change by setting the Java system property **hudson.cli.CLICommand.allowAtSyntax** to **true**. Doing this is strongly discouraged on any network accessible by users who are not Jenkins administrators.

### Referencias

- Jenkins CVE-2024-23897: https://www.jenkins.io/security/advisory/2024-01-24/#SECURITY-3314
- CVE-2024-23897: https://nvd.nist.gov/vuln/detail/CVE-2024-23897

