module.exports = {
  apps: [
    {
      name: "adil-frawdchecker",
      script: "/root/adil/venv/bin/gunicorn",
      args: "config.wsgi:application --workers 3 --bind 0.0.0.0:8394",
      interpreter: "none",
      cwd: "/root/adil/frawdchecker"
    }
  ]
}
