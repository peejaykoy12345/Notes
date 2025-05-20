from flask import render_template, flash, url_for, redirect, request, abort
from flask_login import login_user, current_user, logout_user, login_required
from Notes import app, db, bcrypt
from Notes.forms import RegistrationForm, LoginForm, NoteForm
from Notes.models import User, Note

@app.route('/')
@app.route('/home', methods=['GET', 'POST'])
def home():
    page = request.args.get('page', 1, type=int)
    if current_user.is_authenticated:
        notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.date_posted.desc()).paginate(page=page, per_page=10) 
    else: 
        notes = []
    return render_template('home.html', notes = notes)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('You have been logged in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/create_note', methods=['GET', 'POST'])
@login_required
def create_note():
    form = NoteForm()
    if form.validate_on_submit():
        note = Note(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(note)
        db.session.commit()
        flash('Your note has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_note.html', title='Create Note', form=form)

@app.route('/note/<int:note_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user:
        abort(403)
    db.session.delete(note)
    db.session.commit()
    flash('Your note has been deleted!', 'success')
    return redirect(url_for('home'))

@app.route('/note/<int:note_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user:
        abort(403)
    form = NoteForm()
    if form.validate_on_submit():
        note.title = form.title.data
        note.content = form.content.data
        db.session.commit()
        flash('Your note has been updated!', 'success')
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.title.data = note.title
        form.content.data = note.content
    return render_template('create_note.html', title='Edit Note', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))