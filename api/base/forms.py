from django.contrib.auth.models import User
from .models import Document
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm

class CustomUserCreationForm(UserCreationForm):
    username = forms.CharField(
        label="Enter Username",
        widget=forms.TextInput(
            attrs={"class": "form-control", "placeholder": "Enter your username"}
        ),
    )
    email = forms.EmailField(
        label="Enter email",
        widget=forms.EmailInput(
            attrs={"class": "form-control", "placeholder": "Enter your email"}
        ),
    )
    password1 = forms.CharField(
        label="Enter password",
        widget=forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "Enter your password"}
        ),
    )
    password2 = forms.CharField(
        label="Confirm password",
        widget=forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "Confirm your password"}
        ),
    )

    def save(self):
        user = User.objects.get(email=self.cleaned_data["email"])
        user.username = self.cleaned_data['username']
        user.set_password(self.cleaned_data['password1'])
        user.save()
        return user

    class Meta:
        model = User
        fields = ["username", "email", "password1", "password2"]


class UserLoginForm(AuthenticationForm):
    username = forms.CharField(
        widget=forms.TextInput(
            attrs={"class": "form-control", "placeholder": "Enter your username"}
        )
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "Enter your password"}
        )
    )


class UploadFileForm(forms.ModelForm):
    file = forms.FileField(widget=forms.FileInput(attrs={"class": "form-control"}))

    class Meta:
        model = Document
        fields = (
            "name",
            "file",
        )


class UserDetailsForm(forms.Form):
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user", None)
        super(UserDetailsForm, self).__init__(*args, **kwargs)

    username = forms.CharField(label="Username", min_length=4, max_length=150)
    email = forms.EmailField(label="Email")

    def save(self, commit=True):
        obj, created = User.objects.get_or_create(username=self.user.username)
        obj.username = self.cleaned_data["username"]
        obj.email = self.cleaned_data["email"]
        obj.save()
        return obj
