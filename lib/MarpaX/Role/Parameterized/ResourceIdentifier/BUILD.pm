use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::BUILD;

# ABSTRACT: BUILD role for Resource Identifiers as per RFC3986 and RFC3987

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use MarpaX::Role::Parameterized::ResourceIdentifier::Types -all;
use Moo::Role;
use MooX::Role::Parameterized;
use Types::Standard -all;

#
# This parameterized role just makes sure that trigger on input is installed
# after class creation. After class creation, because there is no control
# on when an attribute trigger is fired. In particular this can cause a problem
# when trigger calls the Marpa action that is using a callback that is using something
# setted by the new method -;
#
# And after all, a trigger is nothing else but an around method isn't it. In the BUILD
# method we call explicitely the trigger (because we know all attributes has been setted)
# and then install it to handle the case of Resource Identifier production.
#
our $setup    = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->instance;

role {
  my $params = shift;

  # -----------------------
  # Sanity checks on params
  # -----------------------
  my %PARAMS = ();
  map { $PARAMS{$_} = $params->{$_} } qw/whoami input_attribute_name input_trigger_name/;
  #
  # We will not insert methods in the role but in the calling package
  #
  croak 'whoami must exist and do Str' unless Str->check($PARAMS{whoami});
  my $whoami = $PARAMS{whoami};
  #
  # Check on input name and trigger
  #
  croak "[$whoami] input_attribute_name must exist and do Str" unless Str->check($params->{input_attribute_name});
  croak "[$whoami] input_trigger_name must exist and do Str"   unless Str->check($params->{input_trigger_name});
  #
  # BUILD is a Moo builtin method: if at this precise compile time, Moo does not see
  # BUILD, it will generate one.
  # So depending on where is placed the "use Moo" we have to do a fresh or around
  #
  my $input_attribute_name = $PARAMS{input_attribute_name};
  my $input_trigger_name   = $PARAMS{input_trigger_name};
  my $around;
  croak "[$whoami] $whoami must have an 'around' method (did you forgot to load Moo ?)" unless CodeRef->check($around = $whoami->can('around'));

  my $build_sub = sub {
    $_[0]->$input_trigger_name($_[0]->$input_attribute_name);
    &$around($input_attribute_name => sub {
               my ($orig, $self) = (shift, shift);
               $self->$input_trigger_name(@_) if (@_);
               $self->$orig(@_);
             }
            );
  };
  my $can_BUILD = $whoami->can('BUILD');
  if ($can_BUILD) {
    &$around(BUILD => sub { my ($orig, $self) = (shift, shift); $self->$orig(@_); $self->$build_sub(@_) });
  } else {
    install_modifier($whoami, 'fresh', BUILD => $build_sub );
  }
};

1;
