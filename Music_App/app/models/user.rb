# == Schema Information
#
# Table name: users
#
#  id              :bigint           not null, primary key
#  email           :string           not null
#  password_digest :string           not null
#  session_token   :string           not null
#  created_at      :datetime         not null
#  updated_at      :datetime         not null
#
class User < ApplicationRecord  #FIGVAPER
    validates :email, :session_token, presence: true, uniqueness: true
    validates :password_digest, presence: true
    validates :password, length: { minimum: 6 }, allow_nil: true
    before_validation :ensure_session_token
    attr_reader :password

    def self.find_by_credentials(email, password) #F
        user = User.find_by(email: email)
        user&.is_password?(password) ? user : nil 
    end
    
    def generate_unique_session_token #G
        loop do
            session_token = SecureRandom::urlsafe_base64(16)
            return session_token unless User.exists?(session_token: session_token)
        end
    end

    def reset_session_token! #R
        self.session_token = generate_unique_session_token
        self.save! 
        self.session_token
    end

    def ensure_session_token #E
        self.session_token ||= generate_unique_session_token
    end

    def password=(password) #P
        self.password_digest = BCrypt::Password.create(password)
        @password = password
    end

    def is_password?(password) #I
        BCrypt::Password.new(self.password_digest).is_password?(password)
    end
end
