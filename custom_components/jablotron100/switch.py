from homeassistant.components.switch import (
	SwitchDeviceClass,
	SwitchEntity,
)
from homeassistant.const import STATE_ON, STATE_OFF
from homeassistant.core import callback, HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from . import JablotronConfigEntry
from .const import EntityType
from .jablotron import Jablotron, JablotronProgrammableOutput, JablotronEntity


async def async_setup_entry(hass: HomeAssistant, config_entry: JablotronConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
	jablotron_instance: Jablotron = config_entry.runtime_data

	@callback
	def add_entities() -> None:
		entities = []

		for entity in jablotron_instance.entities[EntityType.PROGRAMMABLE_OUTPUT].values():
			if entity.id not in jablotron_instance.hass_entities:
				entities.append(JablotronProgrammableOutputEntity(jablotron_instance, entity))

		async_add_entities(entities)

	add_entities()

	config_entry.async_on_unload(
		async_dispatcher_connect(hass, jablotron_instance.signal_entities_added(), add_entities)
	)


class JablotronProgrammableOutputEntity(JablotronEntity, SwitchEntity):

	_control: JablotronProgrammableOutput
	_changed_by: str | None = None

	_attr_device_class = SwitchDeviceClass.SWITCH
	_attr_translation_key = "pg_output"

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronProgrammableOutput,
	) -> None:
		super().__init__(jablotron, control)

		self._attr_translation_placeholders = {
			"pgOutputNo": control.pg_output_number,
		}

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_is_on = self._get_state() == STATE_ON
		self._attr_extra_state_attributes = {
			"changed_by": self._changed_by,
		}

	def set_changed_by(self, user: str) -> None:
		self._changed_by = user
		self.refresh_state()

	def update_state(self, state) -> None:
		# When PG transitions OFF → ON, make sure changed_by reflects the user who triggered it.
		# The d0 3c/3d event packet may arrive after the 0x50 state packet, so use the fresh
		# keypad auth as a fallback.
		if state == STATE_ON and self._get_state() != STATE_ON:
			# Level 1: Check per-PG context (recent auth for this specific output)
			pg_number = self._control.pg_output_number
			fresh_auth = self._jablotron.get_pg_activation_context(pg_number)
			# Level 2: Fall back to global keypad auth
			if fresh_auth is None:
				fresh_auth = self._jablotron.get_fresh_keypad_auth()
			if fresh_auth is not None:
				self._changed_by = fresh_auth

		super().update_state(state)

	def turn_on(self, **kwargs) -> None:
		self._jablotron.toggle_pg_output(self._control.pg_output_number, STATE_ON)
		self.update_state(STATE_ON)

	def turn_off(self, **kwargs) -> None:
		self._jablotron.toggle_pg_output(self._control.pg_output_number, STATE_OFF)
		self.update_state(STATE_OFF)
