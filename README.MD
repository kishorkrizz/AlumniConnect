Alumni Connect is a web application that provides three types of user roles: admin, alumni, and student. The admin role allows users to manage and create profiles for both alumni and students, and provides access to analytics related to alumni status. Additionally, the admin can upload alumni and student data in CSV format, and create posts about upcoming events in the college.

The alumni role enables alumni to update their higher education and employment status, and create posts on the platform for other alumni and students to view and comment on.

The student role allows students to browse and comment on alumni posts, and search for alumni based on their interests.

Overall, Alumni Connect is designed to facilitate interaction and engagement between alumni and students, as well as provide valuable insights into alumni success.
  

To the run this repo , follow these steps
###### Run migrations to migrate tables to database.

```Shell
python manage.py makemigrations
python manage.py migrate
```

###### To run python code.

```Shell
python manage.py shell
```

###### To create groups for Admins and create one Admin.

```Python
from django.contrib.auth.models import User, Group, Permission
from django.contrib.contenttypes.models import ContentType

admins, _ = Group.objects.get_or_create(name='admins')
admins_ct = ContentType.objects.get(app_label='auth', model='user')
is_admin, _ = Permission.objects.get_or_create(name='is_admin', codename='is_admin', content_type=admins_ct)
admins.permissions.add(is_admin)
is_admin.save()
admin,_ = User.objects.get_or_create(username='admin')
admin.set_password('anteater')
admin.groups.add(admins)
admin.save()
admin.has_perm('auth.is_admin')
```

###### To create groups for Alumni.

```Python
from django.contrib.auth.models import User, Group, Permission
from django.contrib.contenttypes.models import ContentType
alumni, _ = Group.objects.get_or_create(name='alumni')
alumni_ct, _ = ContentType.objects.get_or_create(app_label='auth', model='user')
is_alumnus, _ = Permission.objects.get_or_create(name='is_alumnus', codename='is_alumnus', content_type=alumni_ct)
alumni.permissions.add(is_alumnus)
```

###### To create groups for Students.

```Python
from django.contrib.auth.models import User, Group, Permission
from django.contrib.contenttypes.models import ContentType
students, _ = Group.objects.get_or_create(name='students')
students_ct, _ = ContentType.objects.get_or_create(app_label='auth', model='User')
is_student, _ = Permission.objects.get_or_create(name='is_student', codename='is_student', content_type=students_ct)
students.permissions.add(is_student)
```
