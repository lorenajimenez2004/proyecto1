# run.ps1 - crea venv, instala dependencias y ejecuta la app (Windows PowerShell)
param(
    [string]$RequirementsFile = "requirement.txt",
    [string]$VenvDir = ".venv"
)

Write-Host "Creando entorno virtual en $VenvDir..."
python -m venv $VenvDir

$activate = Join-Path $VenvDir 'Scripts\Activate.ps1'
if (Test-Path $activate) {
    Write-Host "Activando entorno virtual..."
    & $activate
} else {
    Write-Host "No se pudo encontrar el script de activación: $activate"
}

Write-Host "Actualizando pip..."
python -m pip install --upgrade pip

if (Test-Path $RequirementsFile) {
    Write-Host "Instalando dependencias desde $RequirementsFile..."
    pip install -r $RequirementsFile
} else {
    Write-Host "No se encontró $RequirementsFile"
}

Write-Host "Iniciando main.py..."
python main.py
