# Static Files Directory

Place your custom static files here:

## Structure

```
static/
├── css/          # Custom CSS files
├── js/           # Custom JavaScript files
└── images/       # Static images (logos, icons, etc.)
```

## Usage

In your templates:

```html
{% load static %}

<link rel="stylesheet" href="{% static 'css/custom.css' %}">
<script src="{% static 'js/custom.js' %}"></script>
<img src="{% static 'images/logo.png' %}" alt="Logo">
```

## Collecting Static Files

Before deployment, run:

```bash
python manage.py collectstatic
```

This will copy all static files to the `staticfiles/` directory.
