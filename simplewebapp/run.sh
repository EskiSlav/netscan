python manage.py migrate
echo "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser('$DJANGO_ADMIN_USER', '$DJANGO_ADMIN_MAIL', '$DJANGO_ADMIN_PASSWORD')" | python manage.py shell
python manage.py runserver 0.0.0.0:8081
