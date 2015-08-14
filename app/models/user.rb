class User < ActiveRecord::Base
	EmailRegex = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
	attr_accessible :name, :email, :password, :password_confirmation
	has_many :microposts #dependent => :destroy
	validates_presence_of :name, :email
	validates_format_of   :email, :with => EmailRegex
	validates_uniqueness_of :email
	attr_accessor :password
	validates_confirmation_of :password
	validates_presence_of :password
	before_save :encrypt_password
	def has_password?(submitted_password) 
		encrypted_password == encrypt(submitted_password)
	end 
	
	def remember_me!
		self.remember_token = encrypt("#{salt}--#{id}--#{Time.now.utc}")
		save_without_validation
	end
	private
	def encrypt_password
		self.encrypted_password = encrypt(password)
	end
	def encrypt(string) 
		secure_hash("#{salt}#{string}")
	end
	def make_salt
		 secure_hash("#{Time.now.utc}#{password}")
	end
	def secure_hash(string) 
		Digest::SHA2.hexdigest(string)
	end
	def self.authenticate(email, submitted_password)
		user = find_by_email(email)
		return nil if user.nil?
		return user if user.has_password?(submitted_password)
	end
end